/* $Id: util.h,v 1.21 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (C) 2008, Parallels, Inc. All rights reserved.
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
	int errcode;
	char errmsg[BUFSIZ];
	int (*logger)(int level, const char *fmt, va_list pvar);
	int (*readpwd)(const char *prompt, char *pass, size_t size);
	char tmpdir[PATH_MAX+1];
	char password[BUFSIZ];
	long tmo;
};

/* data types (vzsock_set() function) */
#define VZSOCK_DATA_HOSTNAME	1 /* dst hostname */
#define VZSOCK_DATA_ADDR	2 /* address */
#define VZSOCK_DATA_FDPAIR	3 /* pair of file descriptors */
#define VZSOCK_DATA_SOCK_DOMAIN	4 /* socket domain */
#define VZSOCK_DATA_SOCK_TYPE	5 /* socket type */
#define VZSOCK_DATA_TMO	6 /* connection timeout */


/* errors code */
#define VZS_ERR_SYSTEM		1
#define VZS_ERR_CANT_CONNECT	2
#define VZS_ERR_BAD_PARAM	3
#define VZS_ERR_TIMEOUT		4
#define VZS_ERR_CONN_BROKEN	5

#ifdef __cplusplus
extern "C" {
#endif 

int vzsock_init(
		int type, 
		struct vzsock_ctx *ctx,
		int (*logger)(int level, const char *fmt, va_list pvar),
		int (*readpwd)(const char *prompt, char *pass, size_t size));
int vzsock_open(struct vzsock_ctx *ctx);
void vzsock_close(struct vzsock_ctx *ctx);
int vzsock_set(struct vzsock_ctx *ctx, int type, void *data, size_t size);

int vzsock_create_conn(struct vzsock_ctx *ctx, 
		char * const args[], void **conn);
int vzsock_close_conn(struct vzsock_ctx *ctx, void *conn);
int vzsock_set_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t size);

#ifdef __cplusplus
}
#endif 

#endif
