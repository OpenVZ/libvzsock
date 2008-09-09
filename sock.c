/* $Id: migssh.cpp,v 1.26 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#include <limits.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
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
static int open_conn(struct vzsock_ctx *ctx, char * const args[], void **conn);
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
static int rcopy(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *task_argv);
static int wait_rcopy(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv);


int _vzs_sock_init(struct vzsock_ctx *ctx, struct vzs_handlers *handlers)
{
	struct sock_data *data;

	if ((data = (struct sock_data *)malloc(sizeof(struct sock_data))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");

	data->domain = PF_INET;
	data->type = SOCK_STREAM;
	data->addr = NULL;
	data->addr_len = 0;

	ctx->type = VZSOCK_SOCK;
	ctx->data = (void *)data;

	handlers->open = open_ctx;
	handlers->close = close_ctx;
	handlers->set = set_ctx;
	handlers->open_conn = open_conn;
	handlers->close_conn = close_conn;
	handlers->set_conn = set_conn;
	handlers->send = _send;
	handlers->recv_str = recv_str;
	handlers->send_data = rcopy;
	handlers->recv_data = wait_rcopy;

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

/* start connection */
static int open_conn(struct vzsock_ctx *ctx, char * const args[], void **conn)
{
	int rc = 0;
	struct sock_data *data = (struct sock_data *)ctx->data;
	struct sock_conn *cn;

	if ((cn = (struct sock_conn *)malloc(sizeof(struct sock_conn))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");
	*conn = cn;

	if (data->addr == NULL)
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, "address not defined");

	if ((cn->sock = socket(data->domain, data->type, 0)) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "socket() : %m");

	if (connect(cn->sock, data->addr, data->addr_len) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "connect() : %m");

	return rc;
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

/* create & open fifo, read pid from fifo and wait end of this proccess */
static int wait_rcopy(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv)
{
	int rc;
	char path[PATH_MAX+1];
	pid_t pid = 0;
	int fd;
	char buffer[BUFSIZ];
	int i;

	snprintf(path, sizeof(path), "%s/pidfile.XXXXXX", ctx->tmpdir);
	if ((fd = mkstemp(path)) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "mkstemp(%s) : %m", path);
	close(fd);
	unlink(path);
	if (mkfifo(path, 0666) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "mkfifo(%s) : %m", path);

	if ((fd = open(path, O_RDONLY)) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "open(%s) : %m", path);

	_vz_set_nonblock(fd);

	snprintf(buffer, sizeof(buffer), "echo $$ > %s/%s;", ctx->tmpdir, path);
	for (i = 0; argv[i]; i++) {
		strncat(buffer, " ", sizeof(buffer)-strlen(buffer)-1);
		strncat(buffer, argv[i], sizeof(buffer)-strlen(buffer)-1);
	}

	if ((rc = _send(ctx, conn, buffer, strlen(buffer) + 1)))
		return rc;

	/* and wait reply */
	if ((rc = vzsock_recv_str(ctx, conn, buffer, sizeof(buffer))))
		return rc;

	/* read pid from fifo */
	if (_vzs_recv_str(ctx, fd, '\n', buffer, sizeof(buffer)) > 0)
			pid = atol(buffer);
	close(fd);
	unlink(path);
	if (pid <= 0)
		return 0;

	/* and wait */
	_vz_logger(ctx, LOG_DEBUG, "wait 'ssh ... tar ...' with pid %d", pid);
	while (kill(pid, 0) == 0)
		sleep(1);
	_vz_logger(ctx, LOG_DEBUG, "continue ... %s", strerror(errno));
	return 0;
}

static int rcopy(struct vzsock_ctx *ctx, void *conn, char * const *argv)
{
	return 0;
}
