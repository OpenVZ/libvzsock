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

#include "vzsock_sample.h"

char progname[NAME_MAX];
int debug = 0;

static void usage()
{
	fprintf(stderr, "Virtuozzo vzmigrate daemon\n");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "%s [-v] [-t]\n", progname);
	fprintf(stderr, "%s -h\n", progname);
	fprintf(stderr,"  Options:\n");
	fprintf(stderr,"    -h/--help           show usage and exit\n");
	fprintf(stderr,"    -v/--verbose        be verbose\n");
}

static int parse_cmd_line(int argc, char *argv[])
{
	int c;
	struct option options[] =
	{
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{ NULL, 0, NULL, 0 }
	};

	while (1)
	{
		c = getopt_long(argc, argv, "vht", options, NULL);
		if (c == -1)
			break;
		switch (c)
		{
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

	struct vzsock_ctx ctx;
	char crtfile[PATH_MAX + 1];
	char keyfile[PATH_MAX + 1];
	char ciphers[BUFSIZ+1];
	void *srv_conn, *conn;

	struct sockaddr_in addr;
	pid_t pid;

	openlog("vzsock_srv", LOG_PID, LOG_USER);

	strncpy(progname, basename(argv[0]), sizeof(progname));
	parse_cmd_line(argc, argv);

	if ((rc = vzsock_init(VZSOCK_SOCK, &ctx, NULL, NULL))) {
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
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(VZSOCK_TEST_PORT);
	if ((rc = vzsock_set(&ctx, VZSOCK_DATA_ADDR, (void *)&addr, sizeof(addr)))) {
		syslog(LOG_ERR, "vzsock_set() return %d", rc);
		goto cleanup_0;
	}

	if ((rc = vzsock_open(&ctx))) {
		syslog(LOG_ERR, "vzsock_open() return %d", rc);
		goto cleanup_0;
	}

	if ((rc = vzsock_listen(&ctx, &srv_conn))) {
		syslog(LOG_ERR, "vzsock_listen() return %d", rc);
		goto cleanup_0;
	}

	syslog(LOG_INFO, "Started");
	while (1) {
		if ((rc = vzsock_accept(&ctx, srv_conn, &conn))) {
			syslog(LOG_ERR, "vzsock_accept() return %d", rc);
			goto cleanup_1;
		}

		pid = fork();
		if (pid < 0) {
			syslog(LOG_ERR, "fork() : %m");
		} else if (pid == 0) {
			vzsock_close_conn(&ctx, srv_conn);
			rc = server(&ctx, conn);
			exit(-rc);
		}
		vzsock_close_conn(&ctx, conn);
	}

cleanup_1:
	vzsock_close_conn(&ctx, srv_conn);

cleanup_0:
	vzsock_close(&ctx);

	closelog();

	return rc;
}

