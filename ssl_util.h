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

int verify_callback(int ok, X509_STORE_CTX *ctx);

#ifdef __cplusplus
}
#endif 

#endif
