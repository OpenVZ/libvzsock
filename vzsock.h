/* $Id: util.h,v 1.21 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) Parallels, 2008
 *
 */

#ifndef __VZSOCK_H__
#define __VZSOCK_H__

#define VZS_SYNC_MSG "vzsock_sync"

#ifdef __cplusplus
extern "C" {
#endif 

/* handlers set */
struct vzs_handlers {
	/* open context */
	int (*open)(struct vzsock_ctx *ctx);
	/* close context */
	void (*close)(struct vzsock_ctx *ctx);
	/* set context parameter(s) */
	int (*set)(struct vzsock_ctx *ctx, int type, void *data, size_t size);

	/* open new connection */
	int (*open_conn)(struct vzsock_ctx *ctx, 
			char * const args[], void **conn);
	/* close connection */
	int (*close_conn)(struct vzsock_ctx *ctx, void *conn);

	int (*connect)(struct vzsock_ctx *ctx, void **conn);
	int (*listen)(struct vzsock_ctx *ctx, void **conn);
	int (*accept)(struct vzsock_ctx *ctx, void *srv_conn, void **conn);

	/* set connection parameter(s) */
	int (*set_conn)(struct vzsock_ctx *ctx, void *conn, 
			int type, void *data, size_t size);
	int (*send)(
			struct vzsock_ctx *ctx, 
			void *conn, 
			const char * data, 
			size_t size);
	int (*recv_str)(
			struct vzsock_ctx *ctx, 
			void *conn, 
			char separator, 
			char *data, 
			size_t size);

/*
        int (*is_connected)(void *conn);
*/
	int (*send_data)(
			struct vzsock_ctx *ctx, 
			void *conn, 
			char * const *argv);
	int (*recv_data)(
			struct vzsock_ctx *ctx, 
			void *conn, 
			char * const *argv);
};

#ifdef __cplusplus
}
#endif 

#endif
