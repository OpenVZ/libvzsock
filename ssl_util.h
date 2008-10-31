/*
 *
 * Copyright (C) 2008, Parallels, Inc. All rights reserved.
 *
 * internal functions for SSL module
 */

#ifndef __VZM_SSL_UTIL_H__
#define __VZM_SSL_UTIL_H__

#include "libvzsock.h"

#ifdef __cplusplus
extern "C" {
#endif 

int ssl_error(struct vzsock_ctx *ctx, int rc, const char *title);

int ssl_select(
		struct vzsock_ctx *ctx, 
		int sock, 
		int err, 
		int silent);

int ssl_shutdown(struct vzsock_ctx *ctx, SSL *ssl, int sock);

int ssl_write(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size,
		int silent);

int ssl_redirect(
		struct vzsock_ctx *ctx, 
		SSL *ssl, 
		int in, 
		int out, 
		int err); 

#ifdef __cplusplus
}
#endif 

#endif
