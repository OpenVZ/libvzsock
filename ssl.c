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
static int open_conn(struct vzsock_ctx *ctx, void *unused, void **conn);
static int wait_conn(struct vzsock_ctx *ctx, void **conn);
static int accept_conn(struct vzsock_ctx *ctx, void *srv_conn, void **conn);
static int close_conn(struct vzsock_ctx *ctx, void *conn);
static int set_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t size);
static int _send(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size);
static int recv_str(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char separator, 
		char *data, 
		size_t size);

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

	data->ctx = NULL;
	data->crtfile[0] = '\0';
	data->keyfile[0] = '\0';
	data->ciphers[0] = '\0';
	data->CAfile[0] = '\0';
	data->CApath[0] = '\0';

	ctx->type = VZSOCK_SSL;
	ctx->data = (void *)data;

	handlers->open = open_ctx;
	handlers->close = close_ctx;
	handlers->set = set_ctx;
	handlers->open_conn = open_conn;
	handlers->wait_conn = wait_conn;
	handlers->accept_conn = accept_conn;
	handlers->close_conn = close_conn;
	handlers->set_conn = set_conn;
	handlers->send = _send;
	handlers->recv_str = recv_str;
/*
	handlers->send_data = send_data;
	handlers->recv_data = recv_data;

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

static int ssl_select(
		struct vzsock_ctx *ctx, 
		int sock, 
		int err, 
		int silent)
{
	int rc;
	fd_set fds;
	struct timeval tv;

	do {
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		tv.tv_sec = ctx->tmo;
		tv.tv_usec = 0;
		/* for SSL_ERROR_WANT_CONNECT and SSL_ERROR_WANT_ACCEPT
		   "select() or poll() for writing on the socket file 
		   descriptor can be used." - SSL_get_error man page */
		if (err == SSL_ERROR_WANT_READ)
			rc = select(sock + 1, &fds, NULL, NULL, &tv);
		else
			rc = select(sock + 1, NULL, &fds, NULL, &tv);
		if (rc == 0) {
			if (silent)
				syslog(LOG_ERR, "timeout (%ld sec)", ctx->tmo);
			else
				_vz_logger(ctx, LOG_ERR, 
					"timeout (%d sec)", ctx->tmo);
			return VZS_ERR_TIMEOUT;
		} else if (rc <= 0) {
			if (silent)
				syslog(LOG_ERR, "select() : %m");
			else
				_vz_logger(ctx, LOG_ERR, "select() : %m");
			return VZS_ERR_CONN_BROKEN;
		}
	} while (!FD_ISSET(sock, &fds));

	return 0;
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
/* TODO : TLSv1_method, SSLv2_method */
	if ((data->ctx = SSL_CTX_new(SSLv3_method())) == NULL)
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
	if (strlen(data->CAfile) || strlen(data->CApath)) {
		/* set CA certificate location */
		if (SSL_CTX_load_verify_locations(data->ctx, 
			strlen(data->CAfile)?data->CAfile:NULL, 
			strlen(data->CApath)?data->CApath:NULL)) 
		{
			rc = ssl_error(ctx, VZS_ERR_CANT_CONNECT, 
				"SSL_CTX_load_verify_locations()");
			goto cleanup_0;
		}
	}
	SSL_CTX_set_verify(data->ctx, mode, NULL);

	return 0;

cleanup_0:
	SSL_CTX_free(data->ctx);
	data->ctx = NULL;
	return rc;
}

static void close_ctx(struct vzsock_ctx *ctx)
{
	struct ssl_data *data = (struct ssl_data *)ctx->data;

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
		/* set socket domain */
		memcpy(&sdata->domain, data, sizeof(sdata->domain));
		break;
	case VZSOCK_DATA_SOCK_TYPE:
		/* set socket type */
		memcpy(&sdata->type, data, sizeof(sdata->type));
		break;
	case VZSOCK_DATA_SOCK_PROTO:
		/* set socket protocol */
		memcpy(&sdata->protocol, data, sizeof(sdata->protocol));
		break;
	case VZSOCK_DATA_ADDR:
		if (sdata->addr)
			free((void *)sdata->addr);

		if ((sdata->addr = (struct sockaddr *)malloc(size)) == NULL)
			return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");
		memcpy(sdata->addr, data, size);
		sdata->addr_len = (socklen_t)size;
		break;
	case VZSOCK_DATA_CRTFILE:
		/* set certificate file name */
		strncpy(sdata->crtfile, (char *)data, sizeof(sdata->crtfile));
		break;
	case VZSOCK_DATA_KEYFILE:
		/* set private key file name */
		strncpy(sdata->keyfile, (char *)data, sizeof(sdata->keyfile));
		break;
	case VZSOCK_DATA_CIPHERS:
		/* set ciphers list */
		strncpy(sdata->ciphers, (char *)data, sizeof(sdata->ciphers));
		break;
	case VZSOCK_DATA_CAFILE:
		/* set CA certificate file */
		strncpy(sdata->CAfile, (char *)data, sizeof(sdata->CAfile));
		break;
	case VZSOCK_DATA_CAPATH:
		/* set CA certificate path */
		strncpy(sdata->CApath, (char *)data, sizeof(sdata->CApath));
		break;
	default:
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
			"Unknown data type : %d", type);
	}
	return 0;
}

static int open_conn(struct vzsock_ctx *ctx, void *unused, void **conn)
{
	int rc = 0;
	int err;
	int sslrc;
	struct ssl_data *data = (struct ssl_data *)ctx->data;
	struct ssl_conn *cn;

	if (data->addr == NULL)
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, "address not defined");

	if ((cn = (struct ssl_conn *)malloc(sizeof(struct ssl_conn))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");

	if ((cn->sock = socket(data->domain, data->type, data->protocol)) == -1) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "socket() : %m");
		goto cleanup_0;
	}

	if (connect(cn->sock, data->addr, data->addr_len) == -1) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "connect() : %m");
		goto cleanup_0;
	}

	if (_vz_set_nonblock(cn->sock)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fcntl() : %m");
		goto cleanup_1;
	}

	/* Create SSL obj */
	if ((cn->ssl = SSL_new(data->ctx)) == NULL) {
		rc = ssl_error(ctx, VZS_ERR_SSL, "SSL_new()");
		goto cleanup_1;
	}
	SSL_set_fd(cn->ssl, cn->sock);
	SSL_set_mode(cn->ssl, SSL_MODE_AUTO_RETRY);

	while (1) {
		if ((sslrc = SSL_connect(cn->ssl)) > 0)
			break;
		err = SSL_get_error(cn->ssl, sslrc);
		if (err == SSL_ERROR_SYSCALL)
		{
			if (sslrc == 0)
				rc = _vz_error(ctx, VZS_ERR_CONN_BROKEN,
					"SSL_connect() : unexpected EOF"); 
			else if (errno == EINTR)
				continue;
			else
				rc = _vz_error(ctx, VZS_ERR_CONN_BROKEN,
					"SSL_connect() : %m");
			goto cleanup_2;
		}
		else if ((err != SSL_ERROR_WANT_WRITE) && \
			(err != SSL_ERROR_WANT_READ) && \
			(err != SSL_ERROR_WANT_CONNECT))
		{
			rc = ssl_error(ctx, VZS_ERR_SSL, "SSL_connect()");
			goto cleanup_2;
		}
		if ((rc = ssl_select(ctx, cn->sock, err, 0)))
			goto cleanup_2;
	}

	*conn = cn;
	return 0;

cleanup_2:
	SSL_free(cn->ssl);
cleanup_1:
	close(cn->sock);
cleanup_0:
	free((void *)cn);
	return rc;
}

static int wait_conn(struct vzsock_ctx *ctx, void **conn)
{
	int rc = 0;
	struct ssl_data *data = (struct ssl_data *)ctx->data;
	struct ssl_conn *cn;

	if (data->addr == NULL)
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, "address not defined");

	if ((cn = (struct ssl_conn *)malloc(sizeof(struct ssl_conn))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");

	if ((cn->sock = socket(data->domain, data->type, data->protocol)) == -1) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "socket() : %m");
		goto cleanup_0;
	}

	if (bind(cn->sock, data->addr, data->addr_len) == -1) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "bind() : %m");
		goto cleanup_1;
	}

	if (listen(cn->sock, SOMAXCONN)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "listen() : %m");
		goto cleanup_1;
	}

	*conn = cn;
	return 0;
cleanup_1:
	close(cn->sock);
	cn->sock = -1;
cleanup_0:
	free((void *)cn);
	return rc;
}

static int accept_conn(struct vzsock_ctx *ctx, void *srv_conn, void **conn)
{
	int rc, sslrc, err;
	struct ssl_data *data = (struct ssl_data *)ctx->data;
	struct ssl_conn *cn;
	struct ssl_conn *srv = (struct ssl_conn *)srv_conn;
	struct sockaddr addr;
	socklen_t addr_len;

	if ((cn = (struct ssl_conn *)malloc(sizeof(struct ssl_conn))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");

	addr_len = sizeof(addr);
	if ((cn->sock = accept(srv->sock, 
		(struct sockaddr *)&addr, &addr_len)) == -1)
	{
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "accept() : %m");
		goto cleanup_0;
	}

	if (_vz_set_nonblock(cn->sock)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fcntl() : %m");
		goto cleanup_1;
	}

	/* Create SSL obj */
	if ((cn->ssl = SSL_new(data->ctx)) == NULL) {
		rc = ssl_error(ctx, VZS_ERR_SSL, "SSL_new()");
		goto cleanup_1;
	}
	SSL_set_fd(cn->ssl, cn->sock);
	SSL_set_mode(cn->ssl, SSL_MODE_AUTO_RETRY);

	while (1) {
		if ((sslrc = SSL_accept(cn->ssl)) > 0)
			break;
		err = SSL_get_error(cn->ssl, sslrc);
		if (err == SSL_ERROR_SYSCALL)
		{
			if (sslrc == 0)
				rc = _vz_error(ctx, VZS_ERR_CONN_BROKEN,
					"SSL_accept() : unexpected EOF"); 
			else if (errno == EINTR)
				continue;
			else
				rc = _vz_error(ctx, VZS_ERR_CONN_BROKEN,
					"SSL_accept() : %m");
			goto cleanup_2;
		}
		else if ((err != SSL_ERROR_WANT_WRITE) && \
			(err != SSL_ERROR_WANT_READ) && \
			(err != SSL_ERROR_WANT_ACCEPT))
		{
			rc = ssl_error(ctx, VZS_ERR_SSL, "SSL_accept()");
			goto cleanup_2;
		}
		if ((rc = ssl_select(ctx, cn->sock, err, 0)))
			goto cleanup_2;
	}
	*conn = cn;
	return 0;

cleanup_2:
	SSL_free(cn->ssl);
cleanup_1:
	close(cn->sock);
cleanup_0:
	free((void *)cn);
	return rc;
}

static int close_conn(struct vzsock_ctx *ctx, void *conn)
{
	int rc = 0;
	int sslrc, err;
	struct ssl_conn *cn = (struct ssl_conn *)conn;

	if (cn->ssl == NULL)
		/* already closed */
		return 0;

	while (1) {
		if ((sslrc = SSL_shutdown(cn->ssl)) > 0)
			break;
		err = SSL_get_error(cn->ssl, sslrc);
		if (err == SSL_ERROR_SYSCALL)
		{
			if (sslrc == 0)
				rc = _vz_error(ctx, VZS_ERR_CONN_BROKEN,
					"SSL_accept() : unexpected EOF"); 
			else if (errno == EINTR)
				continue;
			else
				rc = _vz_error(ctx, VZS_ERR_CONN_BROKEN,
					"SSL_accept() : %m");
			break;
		}
		else if ((err != SSL_ERROR_WANT_WRITE) && \
			(err != SSL_ERROR_WANT_READ))
		{
			rc = ssl_error(ctx, VZS_ERR_SSL, "SSL_shutdown()");
			break;
		}
		if ((rc = ssl_select(ctx, cn->sock, err, 0)))
			break;
	}

	while (close(cn->sock) == -1)
		if (errno != EINTR)
			break;

	SSL_free(cn->ssl);
	cn->ssl = NULL;
	cn->sock = -1;

	return sslrc;
}

static int set_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t size)
{
//	struct ssl_conn *cn = (struct ssl_conn *)conn;

	return 0;
}

/* Write <size> bytes of <data> in non-blocking <ssl> connection.
   In <silent> mode we can't use _vz_error()/_vz_logger() in this function 
   because on server side _vz_error() can call this function to send error 
   message to client side. */
static int ssl_write(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size,
		int silent)
{
	int rc = 0;
	size_t sent = 0;
	int err;
	struct ssl_conn *cn = (struct ssl_conn *)conn;

	if (size == 0)
		return 0;

	while (1) {
		rc = SSL_write(cn->ssl, data + sent, 
			(unsigned int)(size - sent));
		if (rc > 0) {
			sent += rc;
			if (sent >= size)
				return 0;
			continue;
		}
		err = SSL_get_error(cn->ssl, rc);
		if (err == SSL_ERROR_SYSCALL)
		{
			if (rc == 0) {
				if (silent)
					syslog(LOG_ERR,
						"SSL_write() : unexpected EOF");
				else
					_vz_logger(ctx, LOG_ERR, 
						"SSL_write() : unexpected EOF");
				return VZS_ERR_CONN_BROKEN; 
			} else if (errno == EINTR) {
				continue;
			} else {
				if (silent)
					syslog(LOG_ERR, "SSL_write() : %m");
				else
					_vz_logger(ctx, LOG_ERR, 
						"SSL_write() : %m");
				return VZS_ERR_CONN_BROKEN; 
			}
		}
		else if ((err != SSL_ERROR_WANT_WRITE) && \
			(err != SSL_ERROR_WANT_READ)) 
		{
			if (silent)
				syslog(LOG_ERR, "SSL_write() error");
			else
				ssl_error(ctx, VZS_ERR_CONN_BROKEN, 
					"SSL_write()");
			return VZS_ERR_CONN_BROKEN; 
		}
		if ((rc = ssl_select(ctx, cn->sock, err, silent)))
			break;
	}

	return rc;
}

/* send data via ssl connection */
static int _send(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size)
{
	return ssl_write(ctx, conn, data, size, 0);
}

/* 
  read from ssl connection string, separated by <separator>.
  will write '\0' on the end of string
*/
static int recv_str(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char separator, 
		char *data, 
		size_t size)
{
	int rc = 0;
	char * p;
	int err;
	struct ssl_conn *cn = (struct ssl_conn *)conn;

	p = data;
	while (1) {
		rc = SSL_read(cn->ssl, p, 1);
		if (rc > 0) {
			if (*p == separator) {
				*p = '\0';
				return 0;
			}
			p++;
			if (p >= data + size)
				return _vz_error(ctx, VZS_ERR_TOOLONG,
					"SSL_read() : too long message"); 
			continue;
		}
		err = SSL_get_error(cn->ssl, rc);
		if (err == SSL_ERROR_SYSCALL) 
		{
			if (rc == 0)
				return _vz_error(ctx, VZS_ERR_CONN_BROKEN, 
					"SSL_read() : unexpected EOF"); 
			else if (errno == EINTR)
				continue;
			else
				return _vz_error(ctx, VZS_ERR_CONN_BROKEN, 
					"SSL_read() : %m");
		}
		else if ((err != SSL_ERROR_WANT_WRITE) && \
			(err != SSL_ERROR_WANT_READ))
		{
			return ssl_error(ctx, VZS_ERR_CONN_BROKEN, "SSL_read()");
		}
		if ((rc = ssl_select(ctx, cn->sock, err, 0)))
			break;
	}

	return rc;
}
