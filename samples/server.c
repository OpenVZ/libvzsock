/* $Id: vzmd.cpp 130669 2008-07-04 11:19:36Z krasnov $
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
 * vzmigrate daemon
 */
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>

#include <syslog.h>
#include <string.h>
#include <asm/param.h>
#include <libgen.h>
#include <limits.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <stdlib.h>

//#include <vz/libvzsock.h>
#include <libvzsock.h>

#include "sample.h"

char progname[NAME_MAX];
int debug = 0;

char crtfile[PATH_MAX + 1];
char keyfile[PATH_MAX + 1];
char ciphers[BUFSIZ+1];
char CAfile[PATH_MAX + 1];
char CApath[PATH_MAX + 1];

static void usage()
{
	fprintf(stderr, "vzmigrate daemon\n" \
"Usage:\n" \
"%s [-v] [-t]\n" \
"%s -h\n" \
"  Options:\n" \
"       --crtfile <file>  load the certificate from file into ssl\n" \
"       --keyfile <file>  load the private key from file into ssl\n" \
"       --ciphers <file>  sets the list of available ciphers for ssl\n" \
"                         See format in ciphers(1)\n" \
"       --CAfile <file>   load CA trusted certificates from <file>\n" \
"       --CApath <path>   load CA trusted certificates from files from <path>\n" \
"    -v/--verbose         be verbose\n" \
"    -h/--help            show usage and exit\n", progname, progname);
}

static int parse_cmd_line(int argc, char *argv[])
{
	int c;
	struct option options[] =
	{
		{"crtfile", required_argument, NULL, '1'},
		{"keyfile", required_argument, NULL, '2'},
		{"ciphers", required_argument, NULL, '3'},
		{"CAfile", required_argument, NULL, '4'},
		{"CApath", required_argument, NULL, '5'},
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{ NULL, 0, NULL, 0 }
	};

	strcpy(crtfile, "/usr/share/libvzsock/samples/test.crt");
	strcpy(keyfile, "/usr/share/libvzsock/samples/test.key");
	ciphers[0] = '\0';
	CAfile[0] = '\0';
	CApath[0] = '\0';

	while (1)
	{
		c = getopt_long(argc, argv, "vh1:2:3:4:5:", options, NULL);
		if (c == -1)
			break;
		switch (c)
		{
		case '1':
			if (optarg == NULL) {
				usage();
				exit(EXIT_FAILURE);
			}
			strncpy(crtfile, optarg, sizeof(crtfile));
			break;
		case '2':
			if (optarg == NULL) {
				usage();
				exit(EXIT_FAILURE);
			}
			strncpy(keyfile, optarg, sizeof(keyfile));
			break;
		case '3':
			if (optarg == NULL) {
				usage();
				exit(EXIT_FAILURE);
			}
			strncpy(ciphers, optarg, sizeof(ciphers));
			break;
		case '4':
			if (optarg == NULL) {
				usage();
				exit(EXIT_FAILURE);
			}
			strncpy(CAfile, optarg, sizeof(CAfile));
			break;
		case '5':
			if (optarg == NULL) {
				usage();
				exit(EXIT_FAILURE);
			}
			strncpy(CApath, optarg, sizeof(CApath));
			break;
		case 'v':
			debug = 1;
			break;
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int rc = 0;

	int type = VZSOCK_SOCK;
//	int type = VZSOCK_SSL;
	struct vzsock_ctx ctx;
//	void *srv_conn, *conn;
	struct addrinfo hints, *res, *ressave;
	int srvsock, sock;

	pid_t pid;

	openlog("vzsock_srv", LOG_PID, LOG_USER);

	strncpy(progname, basename(argv[0]), sizeof(progname));
	parse_cmd_line(argc, argv);

	if ((rc = vzsock_init(type, &ctx))) {
		syslog(LOG_ERR, "vzsock_init() return %d", rc);
		return rc;
	}
	vzsock_set(&ctx, VZSOCK_DATA_DEBUG, (void *)&debug, sizeof(debug));

	if (type == VZSOCK_SSL) {
		if (strlen(crtfile)) {
			if ((rc = vzsock_set(&ctx, VZSOCK_DATA_CRTFILE, (void *)crtfile, strlen(crtfile)))) {
				syslog(LOG_ERR, "vzsock_set() return %d", rc);
				goto cleanup_0;
			}
		}
		if (strlen(keyfile)) {
			if ((rc = vzsock_set(&ctx, VZSOCK_DATA_KEYFILE, (void *)keyfile, strlen(keyfile)))) {
				syslog(LOG_ERR, "vzsock_set() return %d", rc);
				goto cleanup_0;
			}
		}
		if (strlen(ciphers)) {
			if ((rc = vzsock_set(&ctx, VZSOCK_DATA_CIPHERS, (void *)ciphers, strlen(ciphers)))) {
				syslog(LOG_ERR, "vzsock_set() return %d", rc);
				goto cleanup_0;
			}
		}
		if (strlen(CAfile)) {
			if ((rc = vzsock_set(&ctx, VZSOCK_DATA_CAFILE, (void *)CAfile, strlen(CAfile)))) {
				syslog(LOG_ERR, "vzsock_set() return %d", rc);
				goto cleanup_0;
			}
		}
		if (strlen(CApath)) {
			if ((rc = vzsock_set(&ctx, VZSOCK_DATA_CAFILE, (void *)CApath, strlen(CApath)))) {
				syslog(LOG_ERR, "vzsock_set() return %d", rc);
				goto cleanup_0;
			}
		}
	}

	if ((rc = vzsock_open(&ctx))) {
		syslog(LOG_ERR, "vzsock_open() return %d", rc);
		goto cleanup_0;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	/*
	   AI_PASSIVE flag: the resulting address is used to bind
	   to a socket for accepting incoming connections.
	   So, when the hostname==NULL, getaddrinfo function will
	   return one entry per allowed protocol family containing
	   the unspecified address for that family.
	*/
	hints.ai_flags    = AI_PASSIVE;
	hints.ai_family   = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;

	if ((rc = getaddrinfo(NULL, VZSOCK_TEST_PORT, &hints, &ressave))) {
		syslog(LOG_ERR, "getaddrinfo error: [%s]\n", gai_strerror(rc));
		goto cleanup_0;
	}

	/*
	   Try open socket with each address getaddrinfo returned,
	   until getting a valid listening socket.
	*/
	srvsock = -1;
	for (res = ressave; res; res = res->ai_next) {
		srvsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (srvsock < 0)
			continue;
		if (bind(srvsock, res->ai_addr, res->ai_addrlen) == 0)
			break;
		close(srvsock);
		srvsock = -1;
	}
	if (srvsock < 0) {
		rc = -1;
		syslog(LOG_ERR, "socket error:: could not open socket\n");
		goto cleanup_1;
	}
	if ((rc = vzsock_set(&ctx, VZSOCK_DATA_SOCK_TYPE, (void *)&res->ai_socktype, sizeof(res->ai_socktype)))) {
		syslog(LOG_ERR, "vzsock_set() return %d", rc);
		goto cleanup_2;
	}
	if ((rc = vzsock_set(&ctx, VZSOCK_DATA_SOCK_PROTO, (void *)&res->ai_protocol, sizeof(res->ai_protocol)))) {
		syslog(LOG_ERR, "vzsock_set() return %d", rc);
		goto cleanup_2;
	}

	if (listen(srvsock, SOMAXCONN)) {
		rc = -1;
		syslog(LOG_ERR, "listen() : %m");
		goto cleanup_2;
	}

	syslog(LOG_INFO, "Started");
	while (1) {
		struct sockaddr_storage c_addr;
		socklen_t addr_len = sizeof(c_addr);
		if ((sock = accept(srvsock, (struct sockaddr *)&c_addr, &addr_len)) == -1)
		{
			rc = -1;
			syslog(LOG_ERR, "accept() : %m");
			goto cleanup_2;
		}

		pid = fork();
		if (pid < 0) {
			syslog(LOG_ERR, "fork() : %m");
		} else if (pid == 0) {
			close(srvsock);
			rc = server(&ctx, (void *)&sock);
			exit(-rc);
		}
		close(sock);
	}

cleanup_2:
	close(srvsock);

cleanup_1:
	freeaddrinfo(ressave);

cleanup_0:
	vzsock_close(&ctx);

	closelog();

	return rc;
}

