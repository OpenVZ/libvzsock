/* $Id: ssl.c 130669 2008-07-04 11:19:36Z krasnov $
 *
 * Copyright (c) Parallels, 2008
 *
 */
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <syslog.h>

#include "ssl.h"
#include "util.h"

static int open_ctx(struct vzsock_ctx *ctx);
static void close_ctx(struct vzsock_ctx *ctx);
static int set_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t size);

int _vzs_ssl_init(struct vzsock_ctx *ctx, struct vzs_handlers *handlers)
{
	struct ssl_data *data;

	if ((data = (struct ssl_data *)malloc(sizeof(struct ssl_data))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");

	data->domain = AF_INET;
	data->type = SOCK_STREAM;
	data->protocol = IPPROTO_TCP;
	data->addr = NULL;
	data->addr_len = 0;
	data->mode = VZSOCK_MODE_CLIENT;
	data->sock = -1;

	data->ctx = NULL;
	data->crtfile[0] = '\0';
	data->keyfile[0] = '\0';
	data->ciphers[0] = '\0';

	ctx->type = VZSOCK_SSL;
	ctx->data = (void *)data;

	handlers->open = open_ctx;
	handlers->close = close_ctx;
	handlers->set = set_ctx;
/*
	handlers->open_conn = open_conn;
	handlers->close_conn = close_conn;
	handlers->set_conn = set_conn;
	handlers->send = _send;
	handlers->recv_str = recv_str;
*/
	return 0;
}

/* recursive dump of the error stack */
static void ssl_error_stack(struct vzsock_ctx *ctx)
{
	unsigned long err;
	char buffer[SSL_ERR_STRING_MAXLEN];

	err = ERR_get_error();
	if (err == 0)
		return;
	ssl_error_stack(ctx);
	ERR_error_string_n(err, buffer, sizeof(buffer));
	_vz_logger(ctx, LOG_ERR, "SSL error stack: %lu : %s", err, buffer);
}

static int ssl_error(struct vzsock_ctx *ctx, int rc, const char *title)
{
	char buffer[SSL_ERR_STRING_MAXLEN];
	ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
	ssl_error_stack(ctx);
	return _vz_error(ctx, rc, "%s: %s", title, buffer);
}

/* open context */
static int open_ctx(struct vzsock_ctx *ctx)
{
	int rc = 0;
	struct ssl_data *data = (struct ssl_data *)ctx->data;
	int mode;

	/* Set up the library */
	SSL_library_init();
	SSL_load_error_strings();

	/* Create SSL context (framework) */
	if (data->mode == VZSOCK_MODE_CLIENT)
		data->ctx = SSL_CTX_new(SSLv3_client_method());
	else
		data->ctx = SSL_CTX_new(SSLv3_server_method());
	if (data->ctx == NULL)
		return ssl_error(ctx, VZS_ERR_CANT_CONNECT, "SSL_CTX_new()");

	mode = SSL_VERIFY_NONE;
	if (strlen(data->crtfile)) {
		/* load certificat from file */
		if(SSL_CTX_use_certificate_file(data->ctx, data->crtfile, 
					SSL_FILETYPE_PEM) != 1) {
			rc = ssl_error(ctx, VZS_ERR_CANT_CONNECT, 
					"SSL_CTX_use_certificate_file()");
			goto cleanup_0;
		}
		mode = SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|
					SSL_VERIFY_CLIENT_ONCE;
	}
	if (strlen(data->keyfile)) {
		/* load private key from file */
		if(SSL_CTX_use_PrivateKey_file(data->ctx, data->keyfile, 
					SSL_FILETYPE_PEM) != 1) {
			rc = ssl_error(ctx, VZS_ERR_CANT_CONNECT, 
					"SSL_CTX_use_PrivateKey_file()");
			goto cleanup_0;
		}
	}
	if (strlen(data->ciphers)) {
		/* load available cipher list */
		if (SSL_CTX_set_cipher_list(data->ctx, data->ciphers) == 0) {
			rc = ssl_error(ctx, VZS_ERR_CANT_CONNECT, 
					"SSL_CTX_set_cipher_list()");
			goto cleanup_0;
		}
	}
	if (SSL_CTX_check_private_key(data->ctx) != 1) {
		rc = ssl_error(ctx, VZS_ERR_CANT_CONNECT, "SSL_CTX_check_private_key()");
		goto cleanup_0;
	}
	SSL_CTX_set_verify(data->ctx, mode, NULL);

	if (data->mode == VZSOCK_MODE_SERVER) {
		if (data->addr == NULL)
			rc = _vz_error(ctx, VZS_ERR_BAD_PARAM, "Address does not specified");

		/* Prepare TCP socket for receiving connections */
		if ((data->sock = socket(data->domain, 
					data->type, data->protocol)) == -1) {
			rc = _vz_error(ctx, VZS_ERR_SYSTEM, "socket() : %m");
			goto cleanup_0;
		}

		if (bind(data->sock, (struct sockaddr *)data->addr, 
					sizeof(data->addr_len))) {
			rc = _vz_error(ctx, VZS_ERR_SYSTEM, "bind() : %m");
			goto cleanup_1;
		}

		if (listen(data->sock, SOMAXCONN)) {
			rc = _vz_error(ctx, VZS_ERR_SYSTEM, "listen() : %m");
			goto cleanup_1;
		}
	}
	return 0;

cleanup_1:
	close(data->sock);
cleanup_0:
	SSL_CTX_free(data->ctx);
	return rc;
}

static void close_ctx(struct vzsock_ctx *ctx)
{
	struct ssl_data *data = (struct ssl_data *)ctx->data;

	close(data->sock);
	if (data->ctx)
		SSL_CTX_free(data->ctx);
	if (data->addr)
		free(data->addr);

	free(ctx->data);
	ctx->data = NULL;

	return;
}

static int set_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t size)
{
	struct ssl_data *sdata = (struct ssl_data *)ctx->data;

	switch (type) {
	case VZSOCK_DATA_SOCK_DOMAIN:
	{
		/* set socket domain */
		memcpy(&sdata->domain, data, sizeof(sdata->domain));
		break;
	}
	case VZSOCK_DATA_SOCK_TYPE:
	{
		/* set socket type */
		memcpy(&sdata->type, data, sizeof(sdata->type));
		break;
	}
	case VZSOCK_DATA_SOCK_PROTO:
	{
		/* set socket protocol */
		memcpy(&sdata->protocol, data, sizeof(sdata->protocol));
		break;
	}
	case VZSOCK_DATA_MODE:
	{
		/* set socket type */
		memcpy(&sdata->mode, data, sizeof(sdata->mode));
		if ((sdata->mode != VZSOCK_MODE_CLIENT) && 
				(sdata->mode != VZSOCK_MODE_SERVER))
			return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
				"Invalid mode : %d", sdata->mode);
		break;
	}
	case VZSOCK_DATA_ADDR:
	{
		if (sdata->addr)
			free((void *)sdata->addr);

		if ((sdata->addr = (struct sockaddr *)malloc(size)) == NULL)
			return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");
		memcpy(sdata->addr, data, size);
		sdata->addr_len = (socklen_t)size;
		break;
	}
	case VZSOCK_DATA_CRTFILE:
	{
		/* set certificate file name */
		if (size > sizeof(sdata->crtfile))
			return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
				"ssl, set_ctx(), crtfile : data size (%s) > field size (%d)",
				size, sizeof(sdata->crtfile));
		memcpy(sdata->crtfile, data, size);
		break;
	}
	case VZSOCK_DATA_KEYFILE:
	{
		/* set private key file name */
		if (size > sizeof(sdata->keyfile))
			return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
				"ssl, set_ctx(), keyfile : data size (%s) > field size (%d)",
				size, sizeof(sdata->keyfile));
		memcpy(sdata->keyfile, data, size);
		break;
	}
	case VZSOCK_DATA_CIPHERS:
	{
		/* set ciphers list */
		if (size > sizeof(sdata->ciphers))
			return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
				"ssl, set_ctx(), ciphers : data size (%s) > field size (%d)",
				size, sizeof(sdata->ciphers));
		memcpy(sdata->ciphers, data, size);
		break;
	}
	default:
	{
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
			"Unknown data type : %d", type);
	}
	}
	return 0;
}

