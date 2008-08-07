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

struct sock_conn {
	int domain;
	int type;
	struct sockaddr *addr;
	socklen_t addr_len;
	int sock;
};

#ifdef __cplusplus
extern "C" {
#endif 

int _vz_sock_init(struct vzsock *vzs);

#ifdef __cplusplus
}
#endif 

#endif

