/* $Id: ssh.h,v 1.19 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) Parallels, 2008
 *
 */
#ifndef __VZS_SSH_H_
#define __VZS_SSH_H_

#include <sys/types.h>
#include <limits.h>

#include "libvzsock.h"
#include "vzsock.h"

struct ssh_data {
	char *hostname;
};

struct ssh_conn {
	pid_t pid;
	int in;
	int out;
	char askfile[PATH_MAX + 1];
};

#ifdef __cplusplus
extern "C" {
#endif 

int _vzs_ssh_init(struct vzsock_ctx *ctx, struct vzs_handlers *handlers);

#ifdef __cplusplus
}
#endif 

#endif

