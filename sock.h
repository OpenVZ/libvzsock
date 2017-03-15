/* $Id: ssh.h,v 1.19 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) 2016-2017, Parallels International GmbH
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
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 *
 */
#ifndef __VZS_SOCK_H_
#define __VZS_SOCK_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "libvzsock.h"
#include "vzsock.h"

struct sock_data {
	int domain;
	int type;
	int protocol;
	char *hostname;
	char *service;
	/* address of server - will use for client only */
	size_t addrlen;
	struct sockaddr_storage addr;
};

struct sock_conn {
	int sock;
};

#ifdef __cplusplus
extern "C" {
#endif 

int _vzs_sock_init(struct vzsock_ctx *ctx, struct vzs_handlers *handlers);

#ifdef __cplusplus
}
#endif 

#endif

