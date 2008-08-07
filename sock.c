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
#include "sock.h"
#include "util.h"

static void _vz_sock_clean(struct vzsock_ctx *ctx);
static int _vz_sock_dummy(struct vzsock_ctx *ctx); 
static int _vz_sock_conn(struct vzsock_ctx *ctx, char * const args[]);
static int _vz_sock_close(struct vzsock_ctx *ctx);
static int _vz_sock_set(struct vzsock_ctx *ctx, int type, void *data);


int _vz_sock_init(struct vzsock *vzs)
{
	struct sock_conn *cn;

	vzs->type = VZSOCK_SOCK;
	vzs->clean = _vz_sock_clean;
	vzs->test_conn = _vz_sock_dummy;
	vzs->create_main_conn = _vz_sock_conn;
	vzs->close = _vz_sock_close;
	vzs->set = _vz_sock_set;
//	vzs->recv_str = ;
//	vzs->send = ;
//	vzs->close = ;
//	vzs->is_connected = ;

	if ((cn = (struct sock_conn *)malloc(sizeof(struct sock_conn))) == NULL)
		return _vz_error(&vzs->ctx, VZS_ERR_SYSTEM, "malloc() : %m");

	cn->domain = PF_UNIX;
	cn->type = SOCK_STREAM;
	cn->sock = -1;
	cn->addr = NULL;
	cn->addr_len = 0;

	vzs->ctx.conn = (void *)cn;

	return 0;
} 

static void _vz_sock_clean(struct vzsock_ctx *ctx)
{
//	struct ssh_conn *cn = (struct ssh_conn *)ctx->conn;
	/* do nothing */
	_vz_sock_close(ctx);

	free(ctx->conn);
	ctx->conn = NULL;

	return;
}

static int _vz_sock_dummy(struct vzsock_ctx *ctx) 
{
	return 0;
}

/* start connection */
static int _vz_sock_conn(struct vzsock_ctx *ctx, char * const args[])
{
	int rc = 0;
	struct sock_conn *cn = (struct sock_conn *)ctx->conn;

	if (cn->addr == NULL)
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, "address not defined");

	if ((cn->sock = socket(cn->domain, cn->type, 0)) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "socket() : %m");

	if (connect(cn->sock, cn->addr, cn->addr_len) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "connect() : %m");

	return rc;
}

static int _vz_sock_close(struct vzsock_ctx *ctx)
{
	struct sock_conn *cn = (struct sock_conn *)ctx->conn;
	if (cn->sock == -1)
		/* already closed */
		return 0;

	while (close(cn->sock) == -1)
		if (errno != EINTR)
			break;

	cn->sock = -1;
	return 0;
}

static int _vz_sock_set(struct vzsock_ctx *ctx, int type, void *data)
{
	struct sock_conn *cn = (struct sock_conn *)ctx->conn;

	switch (type) {
	case VZSOCK_DATA_SOCK:
	{
		/* set socket */
		memcpy(&cn->sock, data, sizeof(int));
		break;
	}
	default:
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
			"Unknown data type : %d", type);
	}
	return 0;
}

