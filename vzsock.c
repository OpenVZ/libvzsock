/*
 * Copyright (c) 2006-2017, Parallels International GmbH
 * Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
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
 * Our contact details: Virtuozzo International GmbH, Vordergasse 59, 8200
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
#include <syslog.h>

#include "libvzsock.h"
#include "util.h"
#include "ssh.h"
#include "sock.h"
#include "fd.h"
#ifdef WITH_SSL
#include "ssl.h"
#endif

/* context operations */

int vzsock_init(int type, struct vzsock_ctx *ctx)
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
	ctx->logger = NULL;
	ctx->filter = NULL;
	ctx->password[0] = '\0';
	ctx->lpassword = 0;
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
#ifdef WITH_SSL
	case VZSOCK_SSL:
		if ((rc = _vzs_ssl_init(ctx, handlers)))
			goto cleanup_2;
		break;
#endif
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
	case VZSOCK_DATA_LOGGER:
		ctx->logger = (int (*)(int, const char *, va_list))data;
		break;
	case VZSOCK_DATA_FILTER:
		ctx->filter = (int (*)(const char *, int *, char *, size_t *))data;
		break;
	case VZSOCK_DATA_PASSWORD:
		memcpy(ctx->password, data, size);
		ctx->lpassword = 1;
		break;
	default:
		return handlers->set(ctx, type, data, size);
	}
	return 0;
}

int vzsock_get(struct vzsock_ctx *ctx, int type, void *data, size_t *size)
{
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;

	switch (type) {
	case VZSOCK_DATA_PASSWORD:
		if (*size <= strlen(ctx->password))
			return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
				"It is't enough buffer size (%d) "\
				"for data type : %d", *size, type);
		memcpy(data, ctx->password, strlen(ctx->password)+1);
		break;
	default:
		return handlers->get(ctx, type, data, size);
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
		size_t *size)
{
	char buffer[BUFSIZ];
	int rc, ret;
	struct vzs_handlers *handlers = (struct vzs_handlers *)ctx->handlers;
	size_t sz;

	while (1) {
		sz = sizeof(buffer);
		if ((rc = handlers->recv_str(ctx, conn, separator, buffer, &sz)))
			return rc;
		if (ctx->filter == NULL) {
			if (sz > *size)
				return _vz_error(ctx, VZS_ERR_TOOLONG, 
					"vzsock_recv : too long data (%s bytes)",
					sz);
			*size = sz;
			memcpy(data, buffer, *size);
			return 0;
		}
		ret = ctx->filter(buffer, &ctx->code, data, size);
		if (ret == 0) {
			return 0;
		} else if (ret < 0) {
			return VZS_ERR_FILTER;
		}
	}
	return 0;
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


