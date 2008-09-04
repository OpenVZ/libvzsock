/* $Id: ssh.h,v 1.19 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) Parallels, 2008
 *
 */
#ifndef __VZS_FD_H_
#define __VZS_FD_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "libvzsock.h"
#include "vzsock.h"

struct fd_conn {
	int in;
	int out;
};

#ifdef __cplusplus
extern "C" {
#endif 

int _vzs_fd_init(struct vzsock_ctx *ctx, struct vzs_handlers *handlers);

#ifdef __cplusplus
}
#endif 

#endif

