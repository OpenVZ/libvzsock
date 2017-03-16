/*
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

#ifndef __VZS_SSL_H_
#define __VZS_SSL_H_

#include <sys/types.h>
#include <limits.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

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
	SSL_CTX * ctx;
	char crtfile[PATH_MAX + 1];
	char keyfile[PATH_MAX + 1];
	char CAfile[PATH_MAX + 1];
	char CApath[PATH_MAX + 1];
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

