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
#include <syslog.h>

#include "libvzsock.h"
#include "util.h"
#include "ssh.h"
#include "sock.h"
#include "fd.h"
#include "ssl.h"

/* context operations */

int vzsock_init(
		int type, 
		struct vzsock_ctx *ctx,
		int (*logger)(int level, const char *fmt, va_list pvar),
		int (*readpwd)(const char *prompt, char *pass, size_t size))
{
	int rc;
	char path[PATH_MAX];
	struct vzs_handlers *handlers;
	struct vzs_void_list *clist;

//	openlog("VZM", LOG_PERROR, LOG_USER);

	/* init context */
	if ((handlers = (struct vzs_handlers *)
			malloc(sizeof(struct vzs_handlers))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");
	if ((clist = (struct vzs_void_list *)
			malloc(sizeof(struct vzs_void_list))) == NULL) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");
		goto cleanup_0;
	}
	_vzs_void_list_init(clist);
	ctx->type = type;
	ctx->handlers = (void *)handlers;
	ctx->clist = (void *)clist;
	ctx->debug = 0;
	ctx->errcode = 0;
	ctx->errmsg[0] = '\0';
	ctx->logger = logger;
	ctx->readpwd = readpwd;
	ctx->password[0] = '\0';
	ctx->tmo = VZSOCK_DEF_TMO;
 
	/* create temporary directory (mkdtemp() will set perms 0700) */
	_vzs_get_tmp_dir(path, sizeof(path));
	snprintf(ctx->tmpdir, sizeof(ctx->tmpdir), "%s/vzsock.XXXXXX", path);
	if (mkdtemp(ctx->tmpdir) == NULL) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM,
			"mkdtemp(%s) : %m", ctx->tmpdir);
		goto cleanup_1;
	}

	switch (type) {
	case VZSOCK_SOCK:
		if ((rc = _vzs_sock_init(ctx, handlers)))
			goto cleanup_2;
		break;
	case VZSOCK_SSH:
		if ((rc = _vzs_ssh_init(ctx, handlers)))
			goto cleanup_2;
		break;
	case VZSOCK_FD:
		if ((rc = _vzs_fd_init(ctx, handlers)))
			goto cleanup_2;
		break;
	case VZSOCK_SSL:
		if ((rc = _vzs_ssl_init(ctx, handlers)))
			goto cleanup_2;
		break;
	default:
		rc = _vz_error(ctx, VZS_ERR_BAD_PARAM,
			"undefined vzsock type: %d", type);
		goto cleanup_2;
	}

	return 0;

cleanup_2:
	_vzs_rmdir(ctx, ctx->tmpdir);
cleanup_1:
	free((void *)clist);
cleanup_0:
	free((void *)handlers);

	return rc;
}

int vzsock_open(struct vzsock_ctx *ctx)
{
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;

	return handlers->open(ctx);
}

void vzsock_close(struct vzsock_ctx *ctx)
{
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;
	struct vzs_void_list *clist = (struct vzs_void_list *)ctx->clist;
	struct vzs_void_list_el *cn;

	/* close all connections */
	_vzs_void_list_for_each(clist, cn)
		handlers->close_conn(ctx, cn->p);
	_vzs_void_list_clean(clist);
	free(ctx->clist);
	ctx->clist = NULL;

	handlers->close(ctx);

	free(ctx->handlers);
	ctx->handlers = NULL;

	_vzs_rmdir(ctx, ctx->tmpdir);

//	closelog();
}

int vzsock_set(struct vzsock_ctx *ctx, int type, void *data, size_t size)
{
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;

	switch (type) {
	case VZSOCK_DATA_TMO:
		ctx->tmo = *((long *)data);
		break;
	case VZSOCK_DATA_DEBUG:
		ctx->debug = *((int *)data);
		break;
		default:
		return handlers->set(ctx, type, data, size);
	}
	return 0;
}

/* per-connection functions */

int vzsock_open_conn(struct vzsock_ctx *ctx, void *data, void **conn)
{
	int rc;
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;
	struct vzs_void_list *clist = (struct vzs_void_list *)ctx->clist;

	if ((rc = handlers->open_conn(ctx, data, conn)))
		return rc;
	/* and add into list */
	if (_vzs_void_list_add(clist, *conn))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	return 0;
}
/*
int vzsock_wait_conn(struct vzsock_ctx *ctx, void **conn)
{
	int rc;
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;
	struct vzs_void_list *clist = (struct vzs_void_list *)ctx->clist;

	if ((rc = handlers->wait_conn(ctx, conn)))
		return rc;
	if (_vzs_void_list_add(clist, *conn))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	return 0;
}
*/
int vzsock_accept_conn(struct vzsock_ctx *ctx, void *srv_conn, void **conn)
{
	int rc;
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;
	struct vzs_void_list *clist = (struct vzs_void_list *)ctx->clist;

	if ((rc = handlers->accept_conn(ctx, srv_conn, conn)))
		return rc;
	/* and add into list */
	if (_vzs_void_list_add(clist, *conn))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	return 0;
}

int vzsock_is_open_conn(struct vzsock_ctx *ctx, void *conn) 
{
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;

	return handlers->is_open_conn(conn);
}

int vzsock_close_conn(struct vzsock_ctx *ctx, void *conn)
{
	int rc;
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;
	struct vzs_void_list *clist = (struct vzs_void_list *)ctx->clist;
	struct vzs_void_list_el *cn;

	if ((rc = handlers->close_conn(ctx, conn)))
		return rc;

	/* and remove from list */
	_vzs_void_list_for_each(clist, cn) {
		if (cn->p == conn)
			_vzs_void_list_remove(clist, cn);
	}
	return 0;
}

int vzsock_set_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t size)
{
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;

	return handlers->set_conn(ctx, conn, type, data, size);
}

int vzsock_get_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t *size)
{
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;

	return handlers->get_conn(ctx, conn, type, data, size);
}

int vzsock_send(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size)
{
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;

	return handlers->send(ctx, conn, data, size);
}

int vzsock_send_err_msg(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size)
{
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;

	return handlers->send_err_msg(ctx, conn, data, size);
}

int vzsock_recv(
		struct vzsock_ctx *ctx, 
		void *conn,
		char separator, 
		char *data, 
		size_t size)
{
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;

	return handlers->recv_str(ctx, conn, separator, data, size);
}

/*
 Message format : |code|:message
 code == 0 - server reply,
 also: LOG_ERR LOG_WARNING LOG_NOTICE LOG_INFO LOG_DEBUG 
 Server can send debug message, client will show his message
 NOTE: use only on client(source) side
*/
int vzsock_read_srv_reply(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char *reply, 
		size_t size)
{
	char buffer[BUFSIZ+1];
	int rc;
	char *p;
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;

	/* read/and log debug/info/.. messages until get reply */
	ctx->code = 0;
	while (1) {
		if ((rc = handlers->recv_str(ctx, conn, '\0', buffer, sizeof(buffer))))
			return rc;

		p = buffer;
		if (*p != '|')
			break;
		for (p++; *p && *p != '|'; p++) ;
		if (*p != '|')
			break;
		*(p++) = '\0';
		ctx->code = strtol(buffer+1, NULL, 10);
//		if (ctx->code < LOG_DEBUG)
		if (ctx->code < 1)
			break;

		/* it's a debug message : print and wait reply again
		   To print this message only on debug level (#93813) */
		_vz_logger(ctx, LOG_DEBUG, "%s", p);
	}
	if (reply)
		strncpy(reply, p, size);
	return 0;
}

int vzsock_send_srv_reply(
		struct vzsock_ctx *ctx, 
		void *conn, 
		int code, 
		char *reply) 
{
	char buffer[BUFSIZ+1];
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;

	snprintf(buffer, sizeof(buffer), "|%d|%s", code, reply);
	return handlers->send(ctx, conn, buffer, strlen(buffer)+1);
}

int vzsock_send_data(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv)
{
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;

	return handlers->send_data(ctx, conn, argv);
}

int vzsock_recv_data(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv)
{
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;

	return handlers->recv_data(ctx, conn, argv);
}


