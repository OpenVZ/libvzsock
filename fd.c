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
static int open_conn(struct vzsock_ctx *ctx, void *data, void **conn);
//static int wait_conn(struct vzsock_ctx *ctx, void **conn);
static int accept_conn(struct vzsock_ctx *ctx, void *srv_conn, void **new_conn);
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


int _vzs_fd_init(struct vzsock_ctx *ctx, struct vzs_handlers *handlers)
{
	ctx->type = VZSOCK_FD;
	ctx->data = NULL;

	handlers->open = open_ctx;
	handlers->close = close_ctx;
	handlers->set = set_ctx;
	handlers->open_conn = open_conn;
//	handlers->wait_conn = wait_conn;
	handlers->accept_conn = accept_conn;
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
	return;
}

static int set_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t size)
{
	return 0;
}

/* start connection */
static int open_conn(struct vzsock_ctx *ctx, void *unused, void **conn)
{
	struct fd_conn *cn;

	if ((cn = (struct fd_conn *)malloc(sizeof(struct fd_conn))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");
	*conn = cn;

	return 0;
}
/*
static int wait_conn(struct vzsock_ctx *ctx, void **conn)
{
	return -1;
}
*/
static int accept_conn(struct vzsock_ctx *ctx, void *srv_conn, void **new_conn)
{
	return -1;
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

	return _vzs_writefd(ctx, cn->out, data, size, 0);
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

static void alarm_handler(int sig)
{
	return;
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
	struct sigaction act;
	struct sigaction old_act;

	snprintf(path, sizeof(path), "%s/pidfile.XXXXXX", ctx->tmpdir);
	if ((fd = mkstemp(path)) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "mkstemp(%s) : %m", path);
	close(fd);
	unlink(path);
	if (mkfifo(path, 0666) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "mkfifo(%s) : %m", path);

	snprintf(buffer, sizeof(buffer), "echo $$ > /%s;", path);
	for (i = 0; argv[i]; i++) {
		strncat(buffer, " ", sizeof(buffer)-strlen(buffer)-1);
		strncat(buffer, argv[i], sizeof(buffer)-strlen(buffer)-1);
	}

	if ((rc = vzsock_send_srv_reply(ctx, conn, 0, buffer)))
		return rc;

	/* and wait reply */
	if ((rc = vzsock_recv_str(ctx, conn, buffer, sizeof(buffer))))
		return rc;
	/* open() will lock until so long as anybody will write into fifo */
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	act.sa_handler = alarm_handler;
	sigaction(SIGALRM, &act, &old_act);
	alarm(ctx->tmo);
	fd = open(path, O_RDONLY);
	alarm(0);
	sigaction(SIGALRM, &old_act, NULL);
	if (fd == -1) {
		if (errno == EINTR) {
			return _vz_error(ctx, VZS_ERR_TIMEOUT, 
				"open(%s) lock timeout exceeded", path);
		} else {
			return _vz_error(ctx, VZS_ERR_SYSTEM, "open(%s) : %m", path);
		}
	}

	_vz_set_nonblock(fd);

	/* read pid from fifo */
	if (_vzs_recv_str(ctx, fd, '\n', buffer, sizeof(buffer)) == 0)
			pid = atol(buffer);
	close(fd);
	unlink(path);
	if (pid > 0) {
		/* and wait */
		_vz_logger(ctx, LOG_DEBUG, "wait 'ssh ... tar ...' with pid %d", pid);
		while (kill(pid, 0) == 0)
			sleep(1);
	}
	/* send acknowledgement */
	if ((rc = vzsock_send_srv_reply(ctx, conn, 0, VZS_SYNC_MSG)))
		return rc;
	_vz_logger(ctx, LOG_DEBUG, "continue ... %s", strerror(errno));
	return 0;
}

static int rcopy(struct vzsock_ctx *ctx, void *conn, char * const *argv)
{
	return 0;
}
