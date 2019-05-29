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

#ifndef __VZSOCK_H__
#define __VZSOCK_H__

#define VZS_SYNC_MSG "vzsock_sync"
#define VZS_ACK_MSG "vzsock_ack"

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
	/* get context parameter(s) */
	int (*get)(struct vzsock_ctx *ctx, int type, void *data, size_t *size);

	/* open new connection (connect) */
	int (*open_conn)(struct vzsock_ctx *ctx, void *data, void **conn);
	/* accept incoming connection (accept) */
	int (*accept_conn)(struct vzsock_ctx *ctx, void *srv_conn, void **conn);
	int (*is_open_conn)(void *conn);
	/* close connection */
	int (*close_conn)(struct vzsock_ctx *ctx, void *conn);
	/* set connection parameter(s) */
	int (*set_conn)(struct vzsock_ctx *ctx, void *conn,
			int type, void *data, size_t size);
	/* get connection parameter(s) */
	int (*get_conn)(struct vzsock_ctx *ctx, void *conn,
			int type, void *data, size_t *size);
	int (*send)(
			struct vzsock_ctx *ctx, 
			void *conn, 
			const char * data, 
			size_t size);
	int (*send_err_msg)(
			struct vzsock_ctx *ctx, 
			void *conn, 
			const char * data, 
			size_t size);
	int (*recv_str)(
			struct vzsock_ctx *ctx, 
			void *conn, 
			char separator, 
			char *data, 
			size_t *size);
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
