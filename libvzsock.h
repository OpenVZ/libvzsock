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
#define VZSOCK_DATA_DEBUG	7 /* debug level */


/* errors code */
#define VZS_ERR_SYSTEM		1
#define VZS_ERR_CANT_CONNECT	2
#define VZS_ERR_BAD_PARAM	3
#define VZS_ERR_TIMEOUT		4
#define VZS_ERR_CONN_BROKEN	5
#define VZS_ERR_TOOLONG		6
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
int vzsock_send(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size);
/* read string, separated by <separator>. Will write '\0' on end of string */
int vzsock_recv_str(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char separator, 
		char *data, 
		size_t size);
/* 
 To read reply from server(destination) side as |errcode|:replymessage
 NOTE: use only on client(source) side
 NOTE: you also can send debug/info/warning messages from destination node
*/
int vzsock_read_srv_reply(
		struct vzsock_ctx *ctx, 
		void *conn, 
		int *code, 
		char *reply, 
		size_t size);

/*  */
int vzsock_send_data(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * remote_cmd,
		char * const *argv);
int vzsock_recv_data(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char *path,
		char * const *argv);

#ifdef __cplusplus
}
#endif 

#endif
