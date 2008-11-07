/* $Id: vzmd.cpp 130669 2008-07-04 11:19:36Z krasnov $
 *
 * Copyright (c) Parallels, 2008
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
	fprintf(stderr, "Virtuozzo vzmigrate daemon\n" \
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

	crtfile[0] = '\0';
	keyfile[0] = '\0';
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

//	int type = VZSOCK_SOCK;
	int type = VZSOCK_SSL;
	struct vzsock_ctx ctx;
//	void *srv_conn, *conn;
	int srvsock, sock;

	struct sockaddr_in addr;
	pid_t pid;

	openlog("vzsock_srv", LOG_PID, LOG_USER);

	strcpy(crtfile, "/usr/share/libvzsock/samples/test.crt");
	strcpy(keyfile, "/usr/share/libvzsock/samples/test.key");
	strncpy(progname, basename(argv[0]), sizeof(progname));
	parse_cmd_line(argc, argv);

	if ((rc = vzsock_init(type, &ctx, NULL, NULL))) {
		syslog(LOG_ERR, "vzsock_init() return %d", rc);
		return rc;
	}
	vzsock_set(&ctx, VZSOCK_DATA_DEBUG, (void *)&debug, sizeof(debug));

	if (strlen(crtfile)) {
		if ((rc = vzsock_set(&ctx, VZSOCK_DATA_CRTFILE, 
				(void *)crtfile, strlen(crtfile)))) {
			syslog(LOG_ERR, "vzsock_set() return %d", rc);
			goto cleanup_0;
		}
	}
	if (strlen(keyfile)) {
		if ((rc = vzsock_set(&ctx, VZSOCK_DATA_KEYFILE, 
				(void *)keyfile, strlen(keyfile)))) {
			syslog(LOG_ERR, "vzsock_set() return %d", rc);
			goto cleanup_0;
		}
	}
	if (strlen(ciphers)) {
		if ((rc = vzsock_set(&ctx, VZSOCK_DATA_CIPHERS, 
				(void *)ciphers, strlen(ciphers)))) {
			syslog(LOG_ERR, "vzsock_set() return %d", rc);
			goto cleanup_0;
		}
	}
	if (strlen(CAfile)) {
		if ((rc = vzsock_set(&ctx, VZSOCK_DATA_CAFILE, 
				(void *)CAfile, strlen(CAfile)))) {
			syslog(LOG_ERR, "vzsock_set() return %d", rc);
			goto cleanup_0;
		}
	}
	if (strlen(CApath)) {
		if ((rc = vzsock_set(&ctx, VZSOCK_DATA_CAFILE, 
				(void *)CApath, strlen(CApath)))) {
			syslog(LOG_ERR, "vzsock_set() return %d", rc);
			goto cleanup_0;
		}
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(VZSOCK_TEST_PORT);
/*
	if ((rc = vzsock_set(&ctx, VZSOCK_DATA_ADDR, 
			(void *)&addr, sizeof(addr)))) 
	{
		syslog(LOG_ERR, "vzsock_set() return %d", rc);
		goto cleanup_0;
	}
*/
	if ((rc = vzsock_open(&ctx))) {
		syslog(LOG_ERR, "vzsock_open() return %d", rc);
		goto cleanup_0;
	}

	if ((srvsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		rc = -1;
		syslog(LOG_ERR, "socket() : %m");
		goto cleanup_0;
	}

	if (bind(srvsock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		rc = -1;
		syslog(LOG_ERR, "bind() : %m");
		goto cleanup_1;
	}

	if (listen(srvsock, SOMAXCONN)) {
		rc = -1;
		syslog(LOG_ERR, "listen() : %m");
		goto cleanup_1;
	}

	syslog(LOG_INFO, "Started");
	while (1) {
		struct sockaddr c_addr;
		socklen_t addr_len;

		addr_len = sizeof(c_addr);
		if ((sock = accept(srvsock, 
			(struct sockaddr *)&c_addr, &addr_len)) == -1)
		{
			rc = -1;
			syslog(LOG_ERR, "accept() : %m");
			goto cleanup_1;
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

cleanup_1:
	close(srvsock);

cleanup_0:
	vzsock_close(&ctx);

	closelog();

	return rc;
}

