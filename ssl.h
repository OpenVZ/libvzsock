/* $Id: ssh.h,v 1.19 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) Parallels, 2008
 *
 */
#ifndef __VZS_SSL_H_
#define __VZS_SSL_H_

#include <sys/types.h>
#include <limits.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "libvzsock.h"
#include "vzsock.h"

/*
 AFAIK there are free ports, according
 http://www.iana.org/assignments/port-numbers
*/
#define VZMD_DEF_PORT 4422
 
/* see ERR_error_string man page */
#define SSL_ERR_STRING_MAXLEN 121

struct ssl_data {
	int domain;
	int type;
	int protocol;
	struct sockaddr *addr;
	socklen_t addr_len;
	int mode; /* server or client */
	int sock; /* listen socket */
	SSL_CTX * ctx;
	char crtfile[PATH_MAX + 1];
	char keyfile[PATH_MAX + 1];
	char ciphers[BUFSIZ+1];
//	X509 *cert;
};

struct ssl_conn {
	int sock;
	SSL * ssl;
};

#ifdef __cplusplus
extern "C" {
#endif 

int _vzs_ssl_init(struct vzsock_ctx *ctx, struct vzs_handlers *handlers);

#ifdef __cplusplus
}
#endif 

#endif

