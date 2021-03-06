/*
 * Copyright (c) 2016-2017, Parallels International GmbH
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

#ifndef __LIBVZM_H__
#define __LIBVZM_H__

#include <stdio.h>
#include <stdarg.h>
#include <limits.h>

/* supported connection types */
#define VZSOCK_UNDEF	0
#define VZSOCK_SOCK	1 /* plain socket */
#define VZSOCK_SSH	2
#define VZSOCK_SSL	3
#define VZSOCK_FD	4

/* default timeout */
#define VZSOCK_DEF_TMO 3600

struct vzsock_ctx {
	int type;
	/* handlers for this vzsock type */
	void *handlers;
	/* list of connections */
	void *clist;
	/* specific data */
	void *data;
	int debug;
	int code; /* reply code from server side, used on client only */ 
	int errcode;
	char errmsg[BUFSIZ];
	int (*logger)(int level, const char *fmt, va_list pvar);
	int (*filter)(const char *buffer, int *code, char *data, size_t *size);
	char tmpdir[PATH_MAX+1];
	char password[BUFSIZ];
	int lpassword; /* is password defined by vzsock_set() */
	long tmo;
};

/* data types (vzsock_set() function) */
#define VZSOCK_DATA_HOSTNAME	1 /* dst hostname */
#define VZSOCK_DATA_ADDR	2 /* address */
#define VZSOCK_DATA_FDPAIR	3 /* pair of file descriptors */
#define VZSOCK_DATA_SOCK_DOMAIN	4 /* socket domain */
#define VZSOCK_DATA_SOCK_TYPE	5 /* socket type */
#define VZSOCK_DATA_SOCK_PROTO	6 /* socket protocol */
#define VZSOCK_DATA_TMO		7 /* connection timeout */
#define VZSOCK_DATA_DEBUG	8 /* debug level */
#define VZSOCK_DATA_CRTFILE	9 /* certificate file name */
#define VZSOCK_DATA_KEYFILE	10 /* private key file name */
#define VZSOCK_DATA_CIPHERS	11 /* ciphers list */
#define VZSOCK_DATA_CAFILE	12 /* CA certificate file */
#define VZSOCK_DATA_CAPATH	13 /* CA certificate path */
#define VZSOCK_DATA_PASSWORD	14 /* password */
#define VZSOCK_DATA_LOGGER	15 /* set logger function */
#define VZSOCK_DATA_FILTER	16 /* set read filter function */
#define VZSOCK_DATA_ARGS	17 /* add arguments list */
#define VZSOCK_DATA_SERVICE	18 /* dst service(port) */
#define VZSOCK_DATA_FDSOCK	19 /* file descriptor */
#define VZSOCK_DATA_BLOCKING	20 /* socket blocking mode */

/* errors code */
#define VZS_ERR_SYSTEM		1
#define VZS_ERR_CANT_CONNECT	2
#define VZS_ERR_BAD_PARAM	3 /* invalid parameter value */
#define VZS_ERR_TIMEOUT		4 /* timeout exceeded */
#define VZS_ERR_CONN_BROKEN	5
#define VZS_ERR_TOOLONG		6 /* too long message */
#define VZS_ERR_SSL		7 /* SSL error */
#define VZS_ERR_FILTER		8 /* incoming messages filter error */

#ifdef __cplusplus
extern "C" {
#endif 

int vzsock_init(int type, struct vzsock_ctx *ctx);
int vzsock_open(struct vzsock_ctx *ctx);
void vzsock_close(struct vzsock_ctx *ctx);
int vzsock_set(struct vzsock_ctx *ctx, int type, void *data, size_t size);
int vzsock_get(struct vzsock_ctx *ctx, int type, void *data, size_t *size);
int vzsock_open_conn(struct vzsock_ctx *ctx, void *data, void **conn);
int vzsock_accept_conn(struct vzsock_ctx *ctx, void *srv_conn, void **conn);
int vzsock_is_open_conn(struct vzsock_ctx *ctx, void *conn);
int vzsock_close_conn(struct vzsock_ctx *ctx, void *conn);
int vzsock_set_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t size);
int vzsock_get_conn(struct vzsock_ctx *ctx, void *conn,
		int type, void *data, size_t *size);
int vzsock_send(
		struct vzsock_ctx *ctx,
		void *conn,
		const char * data,
		size_t size);
int vzsock_send_err_msg(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size);
/* read string, separated by <separator>. Will write '\0' on end of string */
int vzsock_recv(
		struct vzsock_ctx *ctx, 
		void *conn,
		char separator, 
		char *data, 
		size_t *size);
#define vzsock_recv_str(ctx, conn, data, size) \
		vzsock_recv((ctx), (conn), ('\0'), (data), (size))
/*  */
int vzsock_send_data(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv);
int vzsock_recv_data(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv);

#ifdef __cplusplus
}
#endif 

#endif
