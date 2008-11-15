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
#include "ssl_util.h"

static int open_ctx(struct vzsock_ctx *ctx);
static void close_ctx(struct vzsock_ctx *ctx);
static int set_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t size);
static int get_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t *size);
static int open_conn(struct vzsock_ctx *ctx, void *unused, void **conn);
static int accept_conn(struct vzsock_ctx *ctx, void *srv_conn, void **conn);
static int is_open_conn(void *conn);
static int close_conn(struct vzsock_ctx *ctx, void *conn);
static int set_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t size);
static int get_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t *size);
static int _send(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size);
static int _send_err_msg(
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
static int send_data(
		struct vzsock_ctx *ctx, 
		void *conn,
		char * const *argv);
static int recv_data(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv);

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
	handlers->get = get_ctx;
	handlers->open_conn = open_conn;
	handlers->accept_conn = accept_conn;
	handlers->is_open_conn = is_open_conn;
	handlers->close_conn = close_conn;
	handlers->set_conn = set_conn;
	handlers->get_conn = get_conn;
	handlers->send = _send;
	handlers->send_err_msg = _send_err_msg;
	handlers->recv_str = recv_str;
	handlers->send_data = send_data;
	handlers->recv_data = recv_data;

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
	if (strlen(data->crtfile) && strlen(data->keyfile)) {
		if (SSL_CTX_check_private_key(data->ctx) != 1) {
			rc = ssl_error(ctx, VZS_ERR_CANT_CONNECT, 
				"SSL_CTX_check_private_key()");
			goto cleanup_0;
		}
	}
	if (strlen(data->CAfile) || strlen(data->CApath)) {
		/* set CA certificate location */
		if (SSL_CTX_load_verify_locations(data->ctx, 
			strlen(data->CAfile)?data->CAfile:NULL, 
			strlen(data->CApath)?data->CApath:NULL) == 0) 
		{
			rc = ssl_error(ctx, VZS_ERR_CANT_CONNECT, 
				"SSL_CTX_load_verify_locations()");
			goto cleanup_0;
		}
	}
	SSL_CTX_set_verify(data->ctx, mode, verify_callback);
	SSL_CTX_set_mode(data->ctx, SSL_MODE_AUTO_RETRY);

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

static int get_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t *size)
{
	return _vz_error(ctx, VZS_ERR_BAD_PARAM, "Unknown data type : %d", type);
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

	_vz_logger(ctx, LOG_DEBUG, "Connection established");
	_vz_logger(ctx, LOG_DEBUG, "SSL connection using %s", 
		SSL_get_cipher(cn->ssl));

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

static int accept_conn(struct vzsock_ctx *ctx, void *sock, void **conn)
{
	int rc, sslrc, err;
	struct ssl_data *data = (struct ssl_data *)ctx->data;
	struct ssl_conn *cn;

	if ((cn = (struct ssl_conn *)malloc(sizeof(struct ssl_conn))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");

	cn->sock = *((int *)sock);
 
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
	_vz_logger(ctx, LOG_DEBUG, "Connection established");
	_vz_logger(ctx, LOG_DEBUG, "SSL connection using %s", 
		SSL_get_cipher(cn->ssl));

	*conn = cn;
	return 0;

cleanup_2:
	SSL_free(cn->ssl);
cleanup_1:
//	close(cn->sock);
//cleanup_0:
	free((void *)cn);
	return rc;
}

static int is_open_conn(void *conn)
{
	struct ssl_conn *cn = (struct ssl_conn *)conn;

	if (conn == NULL)
		return 0;

	if (!SSL_is_init_finished(cn->ssl))
		return 0;

	return 1;
}

static int close_conn(struct vzsock_ctx *ctx, void *conn)
{
	struct ssl_conn *cn = (struct ssl_conn *)conn;

	if (!is_open_conn(conn))
		/* already closed */
		return 0;

	ssl_shutdown(ctx, cn->ssl, cn->sock);

	while (close(cn->sock) == -1)
		if (errno != EINTR)
			break;

	SSL_free(cn->ssl);
	free(conn);

	return 0;
}

static int set_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t size)
{
	return 0;
}

static int get_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t *size)
{
	return 0;
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

/* send data via ssl connection */
static int _send_err_msg(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size)
{
	return ssl_write(ctx, conn, data, size, 1);
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

/* run argv[], and transmit data from argv[0] to ssl connection and vice versa */
static int send_data(
		struct vzsock_ctx *ctx, 
		void *conn,
		char * const *argv)
{
	int rc = 0;
	int sslrc, sslerr;
	int in[2], out[2], err[2];
	int sock;
	SSL *ssl;
	pid_t pid, chpid;
	int status;
//	struct ssl_conn *cn = (struct ssl_conn *)conn;
	struct ssl_data *data = (struct ssl_data *)ctx->data;
	char reply[BUFSIZ];
	struct sockaddr addr;
	socklen_t addr_len;
	fd_set fds;
	struct timeval tv;

	if (data->addr == NULL)
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, "address not defined");

	/* read reply with connection params (port) from server */
	if ((rc = vzsock_read_srv_reply(ctx, conn, reply, sizeof(reply))))
		return rc;

	if (data->domain == PF_INET) {
		/* read port from server reply */
		struct sockaddr_in *saddr = (struct sockaddr_in *)&addr;
		int port;
		char *ptr;
		port = strtol(reply, &ptr, 10);
		if (*ptr != '\0')
			return _vz_error(ctx, VZS_ERR_CONN_BROKEN, 
				"send data : invalid server port number : %s",
				 reply);
		addr_len = sizeof(struct sockaddr_in);
		memcpy(saddr, data->addr, addr_len);
		saddr->sin_port = htons(port);
	} else {
		return _vz_error(ctx, VZS_ERR_SYSTEM, "can't send data for "
			"this communication domain (%d)", data->domain);
	}

	if ((sock = socket(data->domain, data->type, data->protocol)) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "socket() : %m");

	if (_vz_set_nonblock(sock)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fcntl() : %m");
		goto cleanup_0;
	}

	while(1) {
		if (connect(sock, &addr, addr_len) == 0)
			break;
		if (errno == EINTR) {
			continue;
		} else if (errno != EINPROGRESS) {
			rc = _vz_error(ctx, VZS_ERR_SYSTEM, "connect() : %m");
			goto cleanup_0;
		}

		do {
			FD_ZERO(&fds);
			FD_SET(sock, &fds);
			tv.tv_sec = ctx->tmo;
			tv.tv_usec = 0;
			/* writable event - see connect() man page */
			rc = select(sock + 1, NULL, &fds, NULL, &tv);
			if (rc == 0) {
				rc = _vz_error(ctx, VZS_ERR_TIMEOUT, 
					"timeout (%d sec)", ctx->tmo);
				goto cleanup_0;
			} else if (rc <= 0) {
				rc = _vz_error(ctx, VZS_ERR_CONN_BROKEN, 
					"select() : %m");
				goto cleanup_0;
			}
		} while (!FD_ISSET(sock, &fds));
	}


	/* Create SSL obj */
	if ((ssl = SSL_new(data->ctx)) == NULL) {
		rc = ssl_error(ctx, VZS_ERR_SSL, "SSL_new()");
		goto cleanup_0;
	}
	SSL_set_fd(ssl, sock);

	while (1) {
		if ((sslrc = SSL_connect(ssl)) > 0)
			break;
		sslerr = SSL_get_error(ssl, sslrc);
		if (sslerr == SSL_ERROR_SYSCALL)
		{
			if (sslrc == 0)
				rc = _vz_error(ctx, VZS_ERR_CONN_BROKEN,
					"SSL_connect() : unexpected EOF"); 
			else if (errno == EINTR)
				continue;
			else
				rc = _vz_error(ctx, VZS_ERR_CONN_BROKEN,
					"SSL_connect() : %m");
			goto cleanup_1;
		}
		else if ((sslerr != SSL_ERROR_WANT_WRITE) && \
			(sslerr != SSL_ERROR_WANT_READ) && \
			(sslerr != SSL_ERROR_WANT_CONNECT))
		{
			rc = ssl_error(ctx, VZS_ERR_SSL, "SSL_connect()");
			goto cleanup_1;
		}
		if ((rc = ssl_select(ctx, sock, sslerr, 0)))
			goto cleanup_1;
	}

	_vzs_show_args(ctx, "run local task", argv);


	if ((pipe(in) < 0) || (pipe(out) < 0) || (pipe(err) < 0)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "pipe() : %m");
		goto cleanup_2;
	}

#if 0
	/* and wait reply */
	if ((rc = ch_read_retcode(ssl_recv_str, conn)))
		goto cleanup_4;
#endif

	/* run target task */
	if ((chpid = fork()) < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_4;
	} else if (chpid == 0) {
		signal(SIGTERM, SIG_DFL);
		close(in[1]); close(out[0]); close(err[0]);
		dup2(in[0], STDIN_FILENO);
		dup2(out[1], STDOUT_FILENO);
		dup2(err[1], STDERR_FILENO);
		close(in[0]); close(out[1]); close(err[1]);
		execvp(argv[0], argv);
		exit(-VZS_ERR_SYSTEM);
	}
	close(in[0]); close(out[1]); close(err[1]);

	while ((pid = waitpid(chpid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "waitpid() : %m");
		goto cleanup_3;
	} else if (pid == chpid) {
		rc = _vzs_check_exit_status(ctx, (char *)argv[0], status);
		goto cleanup_3;
	}

	if ((rc = ssl_redirect(ctx, ssl, in[1], out[0], err[0])))
		goto cleanup_3;

	while ((pid = waitpid(chpid, &status, 0)) == -1)
		if (errno != EINTR)
			break;

	close(in[1]); close(out[0]); close(err[0]);

	if (pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "waitpid() : %m");
		goto cleanup_2;
	}

	if ((rc = _vzs_check_exit_status(ctx, (char *)argv[0], status)))
		goto cleanup_2;

#if 0
	/* last synchronization */
	if ((rc = ssl_send(conn, cmd, strlen(cmd) + 1)))
		goto cleanup_2;

	if ((rc = ch_read_retcode(ssl_recv_str, conn)))
		goto cleanup_2;
#endif

	goto cleanup_2;
cleanup_4:
	close(in[0]); close(out[1]); close(err[1]);
cleanup_3:
	close(in[1]); close(out[0]); close(err[0]);
cleanup_2:
	ssl_shutdown(ctx, ssl, sock);
cleanup_1:
	SSL_free(ssl);
cleanup_0:
	close(sock);

	return rc;
}

static int recv_data(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv)
{
	int rc = 0;
	int sslrc, sslerr;
	struct ssl_data *data = (struct ssl_data *)ctx->data;
	int srv_sock, cli_sock;
	struct sockaddr srv_addr, cli_addr;
	socklen_t srv_addr_len, cli_addr_len;
	char buffer[BUFSIZ];
	fd_set fds;
	struct timeval tv;
	pid_t pid, chpid;
	int status;
	SSL *ssl;
	int in[2], out[2], err[2];

	if ((srv_sock = socket(data->domain, data->type, data->protocol)) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "socket() : %m");

	if (_vz_set_nonblock(srv_sock)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fcntl() : %m");
		goto cleanup_0;
	}

	/* will listen on random free port with 
	   the local address set to INADDR_ANY */
/* TODO: PF_UNIX ? */
	if (listen(srv_sock, SOMAXCONN)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "listen() : %m");
		goto cleanup_0;
	}
	
	srv_addr_len = sizeof(struct sockaddr);
	if (getsockname(srv_sock, &srv_addr, &srv_addr_len)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "getsockname() : %m");
		goto cleanup_0;
	}
	if (data->domain == PF_INET) {
		/* send port number to client */
		snprintf(buffer, sizeof(buffer), "%d", 
			ntohs(((struct sockaddr_in *)&srv_addr)->sin_port));
		if ((rc = _send(ctx, conn, buffer, strlen(buffer) + 1)))
			goto cleanup_0;
	} else {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "can't receive data for "
			"this communication domain (%d)", data->domain);
		goto cleanup_0;
	}
#if 0
	/* wait and check reply */
	if ((rc = vzsock_recv_str(ctx, cn, buffer, sizeof(buffer)))) {
		_vz_error(ctx, rc, "vzsock_recv_str() return %d", rc);
		goto cleanup_0;
	}
	if (strcmp(buffer, VZS_ACK_MSG)) {
		rc = _vz_error(ctx, VZS_ERR_CONN_BROKEN, 
			"recv data: invalid reply from client (%s)", buffer);
		goto cleanup_0;
	}
#endif
	/* wait connection during timeout */
	while(1) {
		cli_addr_len = sizeof(cli_addr);
		if ((cli_sock = accept(srv_sock, &cli_addr, &cli_addr_len)) >= 0)
			break;
		if (errno == EINTR) {
			continue;
		} else if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
			rc = _vz_error(ctx, VZS_ERR_SYSTEM, "accept() : %m");
			goto cleanup_0;
		}

		do {
			FD_ZERO(&fds);
			FD_SET(srv_sock, &fds);
			tv.tv_sec = ctx->tmo;
			tv.tv_usec = 0;
			/* readable event - see accept() man page */
			rc = select(srv_sock + 1, &fds, NULL, NULL, &tv);
			if (rc == 0) {
				rc = _vz_error(ctx, VZS_ERR_TIMEOUT, 
					"timeout (%d sec)", ctx->tmo);
				goto cleanup_0;
			} else if (rc <= 0) {
				rc = _vz_error(ctx, VZS_ERR_CONN_BROKEN, 
					"select() : %m");
				goto cleanup_0;
			}
		} while (!FD_ISSET(srv_sock, &fds));
	}

	/* Create SSL obj */
	if ((ssl = SSL_new(data->ctx)) == NULL) {
		rc = ssl_error(ctx, VZS_ERR_SSL, "SSL_new()");
		goto cleanup_1;
	}
	SSL_set_fd(ssl, cli_sock);

	while (1) {
		if ((sslrc = SSL_accept(ssl)) > 0)
			break;
		sslerr = SSL_get_error(ssl, sslrc);
		if (sslerr == SSL_ERROR_SYSCALL)
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
		else if ((sslerr != SSL_ERROR_WANT_WRITE) && \
			(sslerr != SSL_ERROR_WANT_READ) && \
			(sslerr != SSL_ERROR_WANT_ACCEPT))
		{
			rc = ssl_error(ctx, VZS_ERR_SSL, "SSL_accept()");
			goto cleanup_2;
		}
		if ((rc = ssl_select(ctx, cli_sock, sslerr, 0)))
			goto cleanup_2;
	}

	if ((pipe(in) < 0) || (pipe(out) < 0) || (pipe(err) < 0)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "pipe() : %m");
		goto cleanup_3;
	}

#if 0
	/* send readiness reply */
	if ((rc = ssl_send(conn, reply, strlen(reply) + 1)))
		goto cleanup_5;
#endif

	_vzs_show_args(ctx, "run local task", argv);

	if ((chpid = fork()) < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_5;
	} else if (chpid == 0) {
		signal(SIGTERM, SIG_DFL);
		close(in[1]); close(out[0]); close(err[0]);
		dup2(in[0], STDIN_FILENO);
		dup2(out[1], STDOUT_FILENO);
		dup2(err[1], STDERR_FILENO);
		close(in[0]); close(out[1]); close(err[1]);
		execvp(argv[0], argv);
		exit(-VZS_ERR_SYSTEM);
	}
	close(in[0]); close(out[1]); close(err[1]);

	while ((pid = waitpid(chpid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "waitpid() : %m");
		goto cleanup_4;
	} else if (pid == chpid) {
		rc = _vzs_check_exit_status(ctx, (char *)argv[0], status);
		goto cleanup_4;
	}

	if ((rc = ssl_redirect(ctx, ssl, in[1], out[0], err[0])))
		goto cleanup_4;

	while ((pid = waitpid(chpid, &status, 0)) == -1)
		if (errno != EINTR)
			break;
	close(in[1]); close(out[0]); close(err[0]);

	if (pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "waitpid() : %m");
		goto cleanup_3;
	}

	if ((rc = _vzs_check_exit_status(ctx, (char *)argv[0], status)))
		goto cleanup_3;
/*
	if ((rc = ssl_recv_str(conn, '\0', buffer, sizeof(buffer))))
		goto cleanup_3;

	if ((rc = ssl_send(conn, reply, strlen(reply) + 1)))
		goto cleanup_3;
*/
	goto cleanup_3;
cleanup_5:
	close(in[0]); close(out[1]); close(err[1]);
cleanup_4:
	close(in[1]); close(out[0]); close(err[0]);
cleanup_3:
	ssl_shutdown(ctx, ssl, cli_sock);
cleanup_2:
	SSL_free(ssl);
cleanup_1:
	close(cli_sock);
cleanup_0:
	close(srv_sock);

	return rc;
}

