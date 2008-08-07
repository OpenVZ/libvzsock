/* $Id: ssh.h,v 1.19 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) Parallels, 2008
 *
 */
#ifndef __VZS_SSH_H_
#define __VZS_SSH_H_

#include <sys/types.h>
#include <limits.h>

struct ssh_conn {
	pid_t pid;
	int in;
	int out;
	char askfile[PATH_MAX + 1];
	char *hostname;
};

#ifdef __cplusplus
extern "C" {
#endif 

int _vz_ssh_init(struct vzsock *vzs);
int _vz_ssh_set(struct vzsock_ctx *ctx, int type, void *data);

#ifdef __cplusplus
}
#endif 

#endif

