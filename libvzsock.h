/* $Id: util.h,v 1.21 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) Parallels, 2008
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

struct vzsock_ctx {
	int debug;
	int errcode;
	char errmsg[BUFSIZ];
	int (*logger)(int level, const char *fmt, va_list pvar);
	int (*readpwd)(const char *prompt, char *pass, size_t size);
	char tmpdir[PATH_MAX+1];
	void *conn;
	char password[BUFSIZ];
};

struct vzsock {
	int type;
	struct vzsock_ctx ctx;
	void (*clean)(struct vzsock_ctx *ctx);
	int (*test_conn)(struct vzsock_ctx *ctx);
	int (*create_main_conn)(struct vzsock_ctx *ctx, char * const args[]);
	int (*set)(struct vzsock_ctx *ctx, int type, void *data);
	int (*close)(struct vzsock_ctx *ctx);
/*
        int (*recv_str)(void *conn,
                char separator, char *data, size_t size);
        int (*send)(void *conn, const char * data, size_t size);
        int (*close)(void *conn);
        int (*is_connected)(void *conn);
*/
};

/* data types (vzsock_set() function) */
#define VZSOCK_DATA_HOSTNAME	1 /* dst hostname */
#define VZSOCK_DATA_SOCK	2 /* socket */
#define VZSOCK_DATA_FDPAIR	3 /* pair of file descriptors */

/* errors code */
#define VZS_ERR_SYSTEM		1
#define VZS_ERR_CANT_CONNECT	2
#define VZS_ERR_BAD_PARAM	3

#ifdef __cplusplus
extern "C" {
#endif 

int vzsock_init(
		int type, 
		struct vzsock *vzs,
		int (*logger)(int level, const char *fmt, va_list pvar),
		int (*readpwd)(const char *prompt, char *pass, size_t size));
void vzsock_clean(struct vzsock *vzs);
int vzsock_test_conn(struct vzsock *vzs);
int vzsock_create_main_conn(struct vzsock *vzs, char * const args[]);
int vzsock_set(struct vzsock *vzs, int type, void *data);

#ifdef __cplusplus
}
#endif 

#endif
