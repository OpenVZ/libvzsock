/* $Id: migssh.cpp,v 1.26 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#include <limits.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslog.h>
#include <unistd.h>
#include <time.h>

#include "libvzsock.h"
#include "sock.h"
#include "util.h"

static int open_ctx(struct vzsock_ctx *ctx);
static void close_ctx(struct vzsock_ctx *ctx);
static int set_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t size);
static int _connect(struct vzsock_ctx *ctx, void *data, void **conn);
static int _listen(struct vzsock_ctx *ctx, void **conn);
static int _accept(struct vzsock_ctx *ctx, void *srv_conn, void **conn);
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
static int send_data(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *task_argv);
static int recv_data(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv);


int _vzs_sock_init(struct vzsock_ctx *ctx, struct vzs_handlers *handlers)
{
	struct sock_data *data;

	if ((data = (struct sock_data *)malloc(sizeof(struct sock_data))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");

	data->domain = AF_INET;
	data->type = SOCK_STREAM;
	data->protocol = IPPROTO_TCP;
	data->addr = NULL;
	data->addr_len = 0;

	ctx->type = VZSOCK_SOCK;
	ctx->data = (void *)data;

	handlers->open = open_ctx;
	handlers->close = close_ctx;
	handlers->set = set_ctx;
	handlers->open_conn = _connect;
	handlers->wait_conn = _listen;
	handlers->accept_conn = _accept;
	handlers->close_conn = close_conn;
	handlers->set_conn = set_conn;
	handlers->send = _send;
	handlers->recv_str = recv_str;
	handlers->send_data = send_data;
	handlers->recv_data = recv_data;

	return 0;
}

/* open context */
static int open_ctx(struct vzsock_ctx *ctx)
{
	return 0;
}

static void close_ctx(struct vzsock_ctx *ctx)
{
	struct sock_data *data = (struct sock_data *)ctx->data;

	if (data->addr)
		free(data->addr);

	free(ctx->data);
	ctx->data = NULL;

	return;
}

static int set_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t size)
{
	struct sock_data *sockdata = (struct sock_data *)ctx->data;

	switch (type) {
	case VZSOCK_DATA_SOCK_DOMAIN:
	{
		/* set socket domain */
		memcpy(&sockdata->domain, data, sizeof(sockdata->domain));
		break;
	}
	case VZSOCK_DATA_SOCK_TYPE:
	{
		/* set socket type */
		memcpy(&sockdata->type, data, sizeof(sockdata->type));
		break;
	}
	case VZSOCK_DATA_SOCK_PROTO:
	{
		/* set socket protocol */
		memcpy(&sockdata->protocol, data, sizeof(sockdata->protocol));
		break;
	}
	case VZSOCK_DATA_ADDR:
	{
		if (sockdata->addr)
			free((void *)sockdata->addr);

		if ((sockdata->addr = (struct sockaddr *)malloc(size)) == NULL)
			return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");
		memcpy(sockdata->addr, data, size);
		sockdata->addr_len = (socklen_t)size;
		break;
	}
	default:
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
			"Unknown data type : %d", type);
	}
	return 0;
}

static int _connect(struct vzsock_ctx *ctx, void *unused, void **conn)
{
	int rc = 0;
	struct sock_data *data = (struct sock_data *)ctx->data;
	struct sock_conn *cn;

	if (data->addr == NULL)
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, "address not defined");

	if ((cn = (struct sock_conn *)malloc(sizeof(struct sock_conn))) == NULL)
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

	*conn = cn;
	return 0;
cleanup_1:
	close(cn->sock);
	cn->sock = -1;
cleanup_0:
	free((void *)cn);
	return rc;
}

static int _listen(struct vzsock_ctx *ctx, void **conn)
{
	int rc = 0;
	struct sock_data *data = (struct sock_data *)ctx->data;
	struct sock_conn *cn;

	if (data->addr == NULL)
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, "address not defined");

	if ((cn = (struct sock_conn *)malloc(sizeof(struct sock_conn))) == NULL)
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

static int _accept(struct vzsock_ctx *ctx, void *srv_conn, void **conn)
{
	struct sock_conn *cn;
	struct sock_conn *srv = (struct sock_conn *)srv_conn;
	int sock;
	struct sockaddr addr;
	socklen_t addr_len;

	addr_len = sizeof(addr);
	if ((sock = accept(srv->sock, (struct sockaddr *)&addr, &addr_len)) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "accept() : %m");

	if ((cn = (struct sock_conn *)malloc(sizeof(struct sock_conn))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");
	cn->sock = sock;
	*conn = cn;

// TODO	_vz_logger(LOG_DEBUG, "Incoming connection from %s", inet_ntoa(addr.sin_addr));

	return 0;
}

static int close_conn(struct vzsock_ctx *ctx, void *conn)
{
	struct sock_conn *cn = (struct sock_conn *)conn;
	if (cn->sock == -1)
		/* already closed */
		return 0;

	while (close(cn->sock) == -1)
		if (errno != EINTR)
			break;

	cn->sock = -1;

	return 0;
}

static int set_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t size)
{
//	struct sock_conn *cn = (struct sock_conn *)conn;

	return 0;
}

static int _send(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size)
{
	struct sock_conn *cn = (struct sock_conn *)conn;

	return _vzs_writefd(ctx, cn->sock, data, size);
}

/* 
  read from nonblocking descriptor <fd> string, separated by <separator>.
  will write '\0' on the end of string
*/
static int recv_str(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char separator, 
		char *data, 
		size_t size)
{
	struct sock_conn *cn = (struct sock_conn *)conn;

	return _vzs_recv_str(ctx, cn->sock, separator, data, size);
}

static int send_data(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv)
{
	int rc = 0;
	pid_t chpid, pid;
	int status;
	struct sock_data *data = (struct sock_data *)ctx->data;
//	struct sock_conn *cn = (struct sock_conn *)conn;
	int sock;
	char reply[BUFSIZ];
	struct sockaddr addr;
	socklen_t addr_len;

	if (data->addr == NULL)
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, "address not defined");

	/* read remote command from server */
	if ((rc = vzsock_read_srv_reply(ctx, conn, reply, sizeof(reply))))
		return rc;

	/* parse reply*/
	switch (data->domain) {
	case PF_INET:
	{
		/* send port number to client */
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
		break;
	}
	default:
	{
		return _vz_error(ctx, VZS_ERR_SYSTEM, "can't send data for "
			"this communication domain (%d)", data->domain);
	}
	}

	if ((sock = socket(data->domain, data->type, data->protocol)) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "socket() : %m");

	if (connect(sock, &addr, addr_len) == -1) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "connect() : %m");
		goto cleanup_0;
	}

	if (ctx->debug) {
		char buffer[BUFSIZ];
		int i;
		buffer[0] = '\0';
		for (i = 0; argv[i]; i++) {
			strncat(buffer, argv[i], sizeof(buffer)-strlen(buffer)-1);
			strncat(buffer, " ", sizeof(buffer)-strlen(buffer)-1);
		}
		_vz_logger(ctx, LOG_DEBUG, "run local task: %s", buffer);
	}

	if ((chpid = fork()) < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_0;
	} else if (chpid == 0) {
		int fd;
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		dup2(sock, STDOUT_FILENO);
		dup2(sock, STDIN_FILENO);
		if ((fd = open("/dev/null", O_WRONLY)) != -1) {
			close(STDERR_FILENO);
			dup2(fd, STDERR_FILENO);
		}
		close(sock);
		execvp(argv[0], (char *const *)argv);
		exit(VZS_ERR_SYSTEM);
	}

//	if ((rc = send(ctx, conn, sync_msg, strlen(sync_msg) + 1)))
//		goto cleanup_4;

	while ((pid = waitpid(chpid, &status, 0)) == -1)
		if (errno != EINTR)
			break;
	if (pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_0;
	}
	rc = _vzs_check_exit_status(ctx, (char *)argv[0], status);

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
	struct sock_data *data = (struct sock_data *)ctx->data;
//	struct sock_conn *cn = (struct sock_conn *)conn;
	int srv_sock, cli_sock;
	struct sockaddr srv_addr, cli_addr;
	socklen_t srv_addr_len, cli_addr_len;
	char buffer[BUFSIZ];
	fd_set fds;
	struct timeval tv;
	pid_t pid, chpid;
	int status;

	if ((srv_sock = socket(data->domain, data->type, data->protocol)) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "socket() : %m");

	_vz_set_nonblock(srv_sock);

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
	switch (data->domain) {
	case PF_INET:
	{
		/* send port number to client */
		snprintf(buffer, sizeof(buffer), "%d", 
			ntohs(((struct sockaddr_in *)&srv_addr)->sin_port));
		if ((rc = _send(ctx, conn, buffer, strlen(buffer) + 1)))
			goto cleanup_0;
		break;
	}
	default:
	{
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "can't receive data for "
			"this communication domain (%d)", data->domain);
		goto cleanup_0;
	}
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
	/* wait connect */
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

	/* run writer */
	if (ctx->debug) {
		int i;
		buffer[0] = '\0';
		for (i = 0; argv[i]; i++) {
			strncat(buffer, argv[i], sizeof(buffer)-strlen(buffer)-1);
			strncat(buffer, " ", sizeof(buffer)-strlen(buffer)-1);
		}
		_vz_logger(ctx, LOG_DEBUG, "run local task: %s", buffer);
	}

	if ((chpid = fork()) < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_1;
	} else if (chpid == 0) {
		int fd;
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		dup2(cli_sock, STDOUT_FILENO);
		dup2(cli_sock, STDIN_FILENO);
/* TODO: to log stderr */
		if ((fd = open("/dev/null", O_WRONLY)) != -1) {
			close(STDERR_FILENO);
			dup2(fd, STDERR_FILENO);
		}
		close(cli_sock);
		close(srv_sock);
		execvp(argv[0], (char *const *)argv);
		exit(VZS_ERR_SYSTEM);
	}
// to send sync message ?
//	if ((rc = send(ctx, conn, sync_msg, strlen(sync_msg) + 1)))
//		goto cleanup_4;

	while ((pid = waitpid(chpid, &status, 0)) == -1)
		if (errno != EINTR)
			break;
	if (pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_1;
	}
	rc = _vzs_check_exit_status(ctx, (char *)argv[0], status);

cleanup_1:
	close(cli_sock);
cleanup_0:
	close(srv_sock);

	return rc;
}

