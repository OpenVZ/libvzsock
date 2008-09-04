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

#include "libvzsock.h"
#include "fd.h"
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


int _vzs_fd_init(struct vzsock_ctx *ctx, struct vzs_handlers *handlers)
{
	ctx->type = VZSOCK_FD;
	ctx->data = NULL;

	handlers->open = open_ctx;
	handlers->close = close_ctx;
	handlers->set = set_ctx;
	handlers->open_conn = open_conn;
	handlers->close_conn = close_conn;
	handlers->set_conn = set_conn;
	handlers->send = _send;
	handlers->recv_str = recv_str;

	return 0;
}

/* open context */
static int open_ctx(struct vzsock_ctx *ctx)
{
	return 0;
}

static void close_ctx(struct vzsock_ctx *ctx)
{
	return;
}

static int set_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t size)
{
	return 0;
}

/* start connection */
static int open_conn(struct vzsock_ctx *ctx, char * const args[], void **conn)
{
	struct fd_conn *cn;

	if ((cn = (struct fd_conn *)malloc(sizeof(struct fd_conn))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");
	*conn = cn;

	return 0;
}

static int close_conn(struct vzsock_ctx *ctx, void *conn)
{
	return 0;
}

/* set connection parameter(s) */
static int set_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t size)
{
	struct fd_conn *cn = (struct fd_conn *)conn;

	switch (type) {
	case VZSOCK_DATA_FDPAIR:
	{
		/* set socket pair */
		int *fd = (int *)data;
		cn->in = fd[0];
		cn->out = fd[1];
		break;
	}
	default:
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
			"Unknown data type : %d", type);
	}
	return 0;
}

static int _send(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size)
{
	struct fd_conn *cn = (struct fd_conn *)conn;

	return _vzs_writefd(ctx, cn->out, data, size);
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
	struct fd_conn *cn = (struct fd_conn *)conn;

	return _vzs_recv_str(ctx, cn->in, separator, data, size);
}

