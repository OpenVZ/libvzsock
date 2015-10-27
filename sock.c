/* $Id: sock.c,v 1.26 2008/06/26 14:40:12 krasnov Exp $
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
static int get_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t *size);
static int _connect(struct vzsock_ctx *ctx, void *data, void **conn);
static int _accept(struct vzsock_ctx *ctx, void *sock, void **conn);
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
		size_t *size);
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

	data->domain = AF_INET6;
	data->type = SOCK_STREAM;
	data->protocol = IPPROTO_TCP;
	data->hostname = NULL;
	data->service = NULL;
	data->addrlen = 0;
	memset((void *)&data->addr, 0, sizeof(data->addr));

	ctx->type = VZSOCK_SOCK;
	ctx->data = (void *)data;

	handlers->open = open_ctx;
	handlers->close = close_ctx;
	handlers->set = set_ctx;
	handlers->get = get_ctx;
	handlers->open_conn = _connect;
	handlers->accept_conn = _accept;
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
	return 0;
}

static void close_ctx(struct vzsock_ctx *ctx)
{
	struct sock_data *data = (struct sock_data *)ctx->data;

	if (data->hostname)
		free(data->hostname);
	if (data->service)
		free(data->service);

	free(ctx->data);
	ctx->data = NULL;

	return;
}

static int set_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t size)
{
	struct sock_data *sockdata = (struct sock_data *)ctx->data;

	switch (type) {
	case VZSOCK_DATA_SOCK_DOMAIN:
		/* set socket domain */
		memcpy(&sockdata->domain, data, sizeof(sockdata->domain));
		break;
	case VZSOCK_DATA_SOCK_TYPE:
		/* set socket type */
		memcpy(&sockdata->type, data, sizeof(sockdata->type));
		break;
	case VZSOCK_DATA_SOCK_PROTO:
		/* set socket protocol */
		memcpy(&sockdata->protocol, data, sizeof(sockdata->protocol));
		break;
	case VZSOCK_DATA_HOSTNAME:
		if (sockdata->hostname)
			free((void *)sockdata->hostname);

		if ((sockdata->hostname = strdup((const char *)data)) == NULL)
			return _vz_error(ctx, VZS_ERR_SYSTEM, "strdup() : %m");
		break;
	case VZSOCK_DATA_SERVICE:
		if (sockdata->service)
			free((void *)sockdata->service);

		if ((sockdata->service = strdup((const char *)data)) == NULL)
			return _vz_error(ctx, VZS_ERR_SYSTEM, "strdup() : %m");
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

static int _connect(struct vzsock_ctx *ctx, void *unused, void **conn)
{
	int rc = 0;
	struct sock_data *data = (struct sock_data *)ctx->data;
	struct sock_conn *cn;
	struct addrinfo hints;
	struct addrinfo *ai;
	struct addrinfo *ailist;

	if (data->hostname == NULL)
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, "hostname not defined");

	if ((cn = (struct sock_conn *)malloc(sizeof(struct sock_conn))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((rc = getaddrinfo(data->hostname, data->service, &hints, &ailist))) {
		fprintf(stderr, "getaddrinfo(\"%s\", \"%s\", ...) error : [%s]\n",
			data->hostname, data->service, gai_strerror(rc));
		goto cleanup_0;
	}

	cn->sock = -1;
	for (ai = ailist; ai; ai = ai->ai_next) {
		cn->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

		if (!(cn->sock < 0)) {
			if (connect(cn->sock, ai->ai_addr, ai->ai_addrlen) == 0)
				break;
			close(cn->sock);
			cn->sock = -1;
		}
	}
	if (cn->sock == -1) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "can not connect to host %s service %s", data->hostname, data->service);
		goto cleanup_1;
	}
	if (_vz_set_nonblock(cn->sock)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fcntl() : %m");
		goto cleanup_2;
	}

	data->domain = ai->ai_family;
	data->type = ai->ai_socktype;
	data->protocol = ai->ai_protocol;
	data->addrlen = ai->ai_addrlen;
	memcpy((void *)&data->addr, (void *)ai->ai_addr, ai->ai_addrlen);

	freeaddrinfo(ailist);
	*conn = cn;
	return 0;
cleanup_2:
	close(cn->sock);
	cn->sock = -1;
cleanup_1:
	freeaddrinfo(ailist);
cleanup_0:
	free((void *)cn);
	return rc;
}
/*
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
*/
static int _accept(struct vzsock_ctx *ctx, void *sock, void **conn)
{
	struct sock_conn *cn;
	struct sock_data *data = (struct sock_data *)ctx->data;
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);

	if ((cn = (struct sock_conn *)malloc(sizeof(struct sock_conn))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");
	cn->sock = *((int *)sock);
	if (getsockname(cn->sock, (struct sockaddr *)&addr, &addrlen))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "getsockname() : %m");
	data->domain = addr.ss_family;
/* TODO : to get socktype and protocol from socket */
	*conn = cn;
	if (_vz_set_nonblock(cn->sock))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "fcntl() : %m");

	return 0;
}

static int is_open_conn(void *conn)
{
	struct sock_conn *cn = (struct sock_conn *)conn;
	int opt;
	socklen_t opt_len;

	if (conn == NULL)
		return 0;
	opt_len = sizeof(opt);
	if (getsockopt(cn->sock, SOL_SOCKET, SO_ERROR, (void *)&opt, &opt_len))
		return 0;

	return 1;
}

static int close_conn(struct vzsock_ctx *ctx, void *conn)
{
	struct sock_conn *cn = (struct sock_conn *)conn;

	if (!is_open_conn(conn))
		/* already closed */
		return 0;

	while (close(cn->sock) == -1)
		if (errno != EINTR)
			break;

	free(conn);

	return 0;
}

static int set_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t size)
{
	struct sock_conn *cn = (struct sock_conn *)conn;

	switch (type) {
	case VZSOCK_DATA_BLOCKING:
	{
		if (size < sizeof(int))
			return _vz_error(ctx, VZS_ERR_BAD_PARAM,
				"It is't enough buffer size (%d) "\
				"for data type : %d", size, type);
		if (__vz_set_block(cn->sock, *((int*)data)))
			return -1;
		break;
	}
	}

	return 0;
}

static int get_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t *size)
{
	struct sock_conn *cn = (struct sock_conn *)conn;

	switch (type) {
	case VZSOCK_DATA_FDSOCK:
	{
		if (*size < sizeof(int))
			return _vz_error(ctx, VZS_ERR_BAD_PARAM,
				"It is't enough buffer size (%d) "\
				"for data type : %d", *size, type);
		*((int*)data) = cn->sock;
		*size = sizeof(int);
		break;
	}
	}

	return 0;
}

static int _send(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size)
{
	struct sock_conn *cn = (struct sock_conn *)conn;
	if (cn == NULL)
		return _vz_error(ctx, VZS_ERR_CONN_BROKEN, "connection does not opened");

	return _vzs_writefd(ctx, cn->sock, data, size, 0);
}

static int _send_err_msg(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size)
{
	struct sock_conn *cn = (struct sock_conn *)conn;
	if (cn == NULL)
		return _vz_error(ctx, VZS_ERR_CONN_BROKEN, "connection does not opened");

	return _vzs_writefd(ctx, cn->sock, data, size, 1);
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
		size_t *size)
{
	struct sock_conn *cn = (struct sock_conn *)conn;
	if (cn == NULL)
		return _vz_error(ctx, VZS_ERR_CONN_BROKEN, "connection does not opened");

	return _vzs_recv_str(ctx, cn->sock, separator, data, size);
}

/* connect to server, get socket, fork child process and redirect process stdin & stdout into socket */
static int send_data(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv)
{
	int rc = 0;
	pid_t chpid, pid;
	int status;
	struct sock_data *data = (struct sock_data *)ctx->data;
	struct sock_conn *cn = (struct sock_conn *)conn;
	int sock;
	char reply[BUFSIZ];
	fd_set fds;
	struct timeval tv;
	size_t size;
	int perr[2];
	FILE *fp;
	char buffer[BUFSIZ];
	int port;
	char *ptr;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);

	if (cn == NULL)
		return _vz_error(ctx, VZS_ERR_CONN_BROKEN, "connection does not opened");

	/* read reply with connection params (port) from server */
	size = sizeof(reply);
	if ((rc = vzsock_recv_str(ctx, conn, reply, &size)))
		return rc;

	/* read port from server reply */
	port = strtol(reply, &ptr, 10);
	if (*ptr != '\0')
		return _vz_error(ctx, VZS_ERR_CONN_BROKEN, "send data : invalid server port number : %s", reply);

	/* get address of main connection and replace port */
	addr_len = data->addrlen;
	memcpy((void *)&addr, (void *)&data->addr, data->addrlen);
	if (addr.ss_family == AF_INET) {
		((struct sockaddr_in *)&addr)->sin_port = htons(port);
		addr_len = sizeof(struct sockaddr_in);
	} else if (addr.ss_family == AF_INET6) {
		((struct sockaddr_in6 *)&addr)->sin6_port = htons(port);
		addr_len = sizeof(struct sockaddr_in6);
	} else {
		return _vz_error(ctx, VZS_ERR_SYSTEM,
			"can't send data for this communication domain (%d)", addr.ss_family);
	}

	if ((sock = socket(data->domain, data->type, data->protocol)) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "socket() : %m");

	if (ctx->tmo && _vz_set_nonblock(sock)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fcntl() : %m");
		goto cleanup_0;
	}

	if (pipe(perr)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "pipe() : %m");
		goto cleanup_0;
	}

	while(1) {
		if (connect(sock, (struct sockaddr *)&addr, addr_len) == 0)
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
	_vzs_show_args(ctx, "", argv);

	if ((chpid = fork()) < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_0;
	} else if (chpid == 0) {
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		dup2(sock, STDOUT_FILENO);
		dup2(sock, STDIN_FILENO);
		/* redirect stderr to pipe */
		close(perr[0]);
		dup2(perr[1], STDERR_FILENO);
		close(perr[1]);
		close(sock);
		execvp(argv[0], (char *const *)argv);
		exit(VZS_ERR_SYSTEM);
	}

//	if ((rc = send(ctx, conn, sync_msg, strlen(sync_msg) + 1)))
//		goto cleanup_4;

	/* read stderr and put to log */
	close(perr[1]);
	if ((fp = fdopen(perr[0], "r")) != NULL) {
		while(fgets(buffer, sizeof(buffer), fp)) {
			if (buffer[strlen(buffer)-1] == '\n')
				buffer[strlen(buffer)-1] = '\0';
			_vz_logger(ctx, LOG_ERR, "%s", buffer);
		}
		fclose(fp);
	}
	close(perr[0]);

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
	close(perr[0]); close(perr[1]);

	return rc;
}

static int recv_data(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv)
{
	int rc = 0;
	struct sock_data *data = (struct sock_data *)ctx->data;
	int srv_sock, cli_sock;
	struct sockaddr_storage srv_addr, cli_addr;
	socklen_t srv_addr_len = sizeof(srv_addr);
	socklen_t cli_addr_len = sizeof(cli_addr);
	char buffer[BUFSIZ];
	fd_set fds;
	struct timeval tv;
	pid_t pid, chpid;
	int status;
	int perr[2];
	FILE *fp;

	if ((srv_sock = socket(data->domain, data->type, data->protocol)) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "socket() : %m");

	if (ctx->tmo && _vz_set_nonblock(srv_sock)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fcntl() : %m");
		goto cleanup_0;
	}

	if (pipe(perr)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "pipe() : %m");
		goto cleanup_0;
	}

	/* will listen on random free port with the local address set to INADDR_ANY */
/* TODO: PF_UNIX ? */
	if (listen(srv_sock, SOMAXCONN)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "listen() : %m");
		goto cleanup_0;
	}

	/* get port number and send to other side */
	if (getsockname(srv_sock, (struct sockaddr *)&srv_addr, &srv_addr_len)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "getsockname() : %m");
		goto cleanup_0;
	}
	if (srv_addr.ss_family == AF_INET) {
		snprintf(buffer, sizeof(buffer), "%d", ntohs(((struct sockaddr_in *)&srv_addr)->sin_port));
	} else if (srv_addr.ss_family == AF_INET6) {
		snprintf(buffer, sizeof(buffer), "%d", ntohs(((struct sockaddr_in6 *)&srv_addr)->sin6_port));
	} else {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "can't receive data for "
			"this communication domain (%d)", srv_addr.ss_family);
		goto cleanup_0;
	}
	/* send port number to client */
	if ((rc = _send(ctx, conn, buffer, strlen(buffer) + 1)))
		goto cleanup_0;
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
		if ((cli_sock = accept(srv_sock, (struct sockaddr *)&cli_addr, &cli_addr_len)) >= 0)
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
	_vzs_show_args(ctx, "", argv);

	if ((chpid = fork()) < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_1;
	} else if (chpid == 0) {
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		dup2(cli_sock, STDOUT_FILENO);
		dup2(cli_sock, STDIN_FILENO);
		/* redirect stderr to pipe */
		close(perr[0]);
		dup2(perr[1], STDERR_FILENO);
		close(perr[1]);
		close(cli_sock);
		close(srv_sock);
		execvp(argv[0], (char *const *)argv);
		exit(VZS_ERR_SYSTEM);
	}
// to send sync message ?
//	if ((rc = send(ctx, conn, sync_msg, strlen(sync_msg) + 1)))
//		goto cleanup_4;

	/* read stderr and put to log */
	close(perr[1]);
	if ((fp = fdopen(perr[0], "r")) != NULL) {
		while(fgets(buffer, sizeof(buffer), fp)) {
			if (buffer[strlen(buffer)-1] == '\n')
				buffer[strlen(buffer)-1] = '\0';
			_vz_logger(ctx, LOG_ERR, "%s", buffer);
		}
		fclose(fp);
	}
	close(perr[0]);

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
	close(perr[0]); close(perr[1]);

	return rc;
}

