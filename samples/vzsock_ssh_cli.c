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
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <libgen.h>
#include <signal.h>

#include <vz/libvzsock.h>

#include "sample.h"

static int logger(int level, const char* fmt, va_list pvar)
{
	va_list ap;
	FILE *fp = (level <= LOG_WARNING) ? stderr : stdout;
	/* put to syslog and to some output also */
	va_copy(ap, pvar);
	vsyslog(level, fmt, ap);
	va_end(ap);
	vfprintf(fp, fmt, pvar);
	fputc('\n', fp);
	return 0;
}

/*
void terminate(int signum)
{
	// send sigterm to all processes in group
	kill(0, SIGTERM);

	unlink(pidfile);
	exit(-MIG_ERR_TERM);
}
*/

int main(int argc, const char *argv[])
{
	int rc;
	struct vzsock_ctx ctx;
	char * const args[] = {"vzsock_ssh_srv", NULL};
	void *conn;
	int debug = LOG_DEBUG;
	char buffer[BUFSIZ]; 
	char lname[PATH_MAX];
	char lpath[PATH_MAX];
	char rpath[PATH_MAX];
	char *p;
	struct sigaction sigact;
	char * const targs[] = { 
			"tar", 
			"-c", 
			"-S", 
			"--ignore-failed-read", 
			"--numeric-owner", 
			"-f", 
			"-", 
			"-C", 
			lpath, 
			lname,
			NULL };

	if (argc != 3) {
		fprintf(stderr, "Usage : %s path hostname\n", argv[0]);
		return 1;
	}
	strncpy(buffer, argv[1], sizeof(buffer));
	strncpy(lname, basename(buffer), sizeof(lname));
	strncpy(lpath, dirname(buffer), sizeof(lpath));
	if ((p = strchr(argv[2], ':'))) {
		strncpy(rpath, p+1, sizeof(rpath));
	} else {
		strcpy(rpath, "/");
	}

	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
//	sigact.sa_handler = terminate;
//	sigaction(SIGTERM, &sigact, NULL);
	sigact.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sigact, NULL);

	if ((rc = vzsock_init(VZSOCK_SSH, &ctx, logger, NULL))) {
		fprintf(stderr, "vzsock_init() return %d\n", rc);
		return -1;
	}
	vzsock_set(&ctx, VZSOCK_DATA_DEBUG, (void *)&debug, sizeof(debug));
	if ((rc = vzsock_set(&ctx, VZSOCK_DATA_HOSTNAME, (void *)argv[2], strlen(argv[2])+1))) {
		fprintf(stderr, "vzsock_set() return %d\n", rc);
		goto cleanup_0;
	}
	if ((rc = vzsock_open(&ctx))) {
		fprintf(stderr, "vzsock_open() return %d\n", rc);
		goto cleanup_0;
	}
/* TODO
	vzsock_set(&ctx, VZSOCK_DATA_ARGS, (void *)&args, sizeof(args));
*/
	if ((rc = vzsock_create_conn(&ctx, args, &conn))) {
		fprintf(stderr, "vzsock_create_conn() return %d\n", rc);
		goto cleanup_0;
	}

	/* send first command and wait reply */
	if ((rc = vzsock_send(&ctx, conn, CMD_INIT, strlen(CMD_INIT)+1))) {
		fprintf(stderr, "vzsock_send() return %d\n", rc);
		goto cleanup_1;
	}
	if ((rc = vzsock_read_srv_reply(&ctx, conn, buffer, sizeof(buffer)))) {
		fprintf(stderr, "vzsock_read_srv_reply() return %d\n", rc);
		goto cleanup_1;
	}
	fprintf(stdout, "reply is %s\n", buffer);

	/* copy dir */
	snprintf(buffer, sizeof(buffer), CMD_COPY " %s", rpath);
	if ((rc = vzsock_send(&ctx, conn, buffer, strlen(buffer)+1))) {
		fprintf(stderr, "vzsock_send() return %d\n", rc);
		goto cleanup_1;
	}
	if ((rc = vzsock_read_srv_reply(&ctx, conn, buffer, sizeof(buffer)))) {
		fprintf(stderr, "vzsock_read_srv_reply() return %d\n", rc);
		goto cleanup_1;
	}
	fprintf(stdout, "reply is %s\n", buffer);
	if ((rc = vzsock_send_data(&ctx, conn, targs))) {
		fprintf(stderr, "vzsock_send_data() return %d\n", rc);
		goto cleanup_1;
	}

	/* close connection */
	if ((rc = vzsock_send(&ctx, conn, CMD_CLOSE, strlen(CMD_CLOSE)+1))) {
		fprintf(stderr, "vzsock_send() return %d\n", rc);
		goto cleanup_1;
	}
	if ((rc = vzsock_read_srv_reply(&ctx, conn, buffer, sizeof(buffer)))) {
		fprintf(stderr, "vzsock_read_srv_reply() return %d\n", rc);
		goto cleanup_1;
	}
	fprintf(stdout, "reply is %s\n", buffer);
cleanup_1:
	vzsock_close_conn(&ctx, conn);
cleanup_0:
	vzsock_close(&ctx);

	return rc;
}
