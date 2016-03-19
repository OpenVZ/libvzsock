/* $Id: migssh.cpp,v 1.26 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) 2006-2016 Parallels IP Holdings GmbH
 *
 * This file is part of OpenVZ libraries. OpenVZ is free software; you can
 * redistribute it and/or modify it under the terms of the GNU Lesser General
 * Public License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/> or write to Free Software Foundation,
 * 51 Franklin Street, Fifth Floor Boston, MA 02110, USA.
 *
 * Our contact details: Parallels IP Holdings GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
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
static int get_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t *size);
static int open_conn(struct vzsock_ctx *ctx, void *data, void **conn);
static int accept_conn(struct vzsock_ctx *ctx, void *srv_conn, void **new_conn);
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
	return _vz_error(ctx, VZS_ERR_BAD_PARAM, "Unknown data type : %d", type);
}

static int get_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t *size)
{
	return _vz_error(ctx, VZS_ERR_BAD_PARAM, "Unknown data type : %d", type);
}

/* start connection */
static int open_conn(struct vzsock_ctx *ctx, void *unused, void **conn)
{
	struct fd_conn *cn;

	if ((cn = (struct fd_conn *)malloc(sizeof(struct fd_conn))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");
	cn->in = -1;
	cn->out = -1;
	*conn = cn;

	return 0;
}

static int accept_conn(struct vzsock_ctx *ctx, void *srv_conn, void **new_conn)
{
	return -1;
}

static int is_open_conn(void *conn)
{
	struct fd_conn *cn = (struct fd_conn *)conn;
	struct stat st;

	if (conn == NULL)
		return 0;
	if (fstat(cn->in, &st))
		return 0;
	if (fstat(cn->out, &st))
		return 0;

	return 1;
}

static int close_conn(struct vzsock_ctx *ctx, void *conn)
{
	free(conn);
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

/* get connection parameter(s) */
static int get_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t *size)
{
	struct fd_conn *cn = (struct fd_conn *)conn;

	switch (type) {
	case VZSOCK_DATA_FDPAIR:
	{
		/* get pair of descriptors */
		int fd[2];

		if (*size < sizeof(fd))
			return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
				"It is't enough buffer size (%d) "\
				"for data type : %d", *size, type);
		fd[0] = cn->in;
		fd[1] = cn->out;
		memcpy(data, (void *)fd, sizeof(fd));
		*size = sizeof(fd);
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

static int _send_err_msg(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size)
{
	struct fd_conn *cn = (struct fd_conn *)conn;

	return _vzs_writefd(ctx, cn->out, data, size, 1);
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
	size_t size;

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

	if ((rc = vzsock_send(ctx, conn, buffer, strlen(buffer)+1)))
		return rc;

	/* and wait reply */
	size = sizeof(buffer);
	if ((rc = vzsock_recv_str(ctx, conn, buffer, &size)))
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
	size = sizeof(buffer);
	if (_vzs_recv_str(ctx, fd, '\n', buffer, &size) == 0)
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
	if ((rc = vzsock_send(ctx, conn, VZS_SYNC_MSG, strlen(VZS_SYNC_MSG)+1)))
		return rc;
	_vz_logger(ctx, LOG_DEBUG, "continue ... %s", strerror(errno));
	return 0;
}

static int rcopy(struct vzsock_ctx *ctx, void *conn, char * const *argv)
{
	return 0;
}
