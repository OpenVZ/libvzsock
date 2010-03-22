/* $Id: ssh.h,v 1.19 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) Parallels, 2008
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

