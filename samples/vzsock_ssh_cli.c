#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libvzsock.h>
#include <string.h>
#include <syslog.h>

#include "vzsock_sample.h"

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

int main(int argc, const char *argv[])
{
	int rc;
	char *path;
	struct vzsock_ctx ctx;
	char * const args[] = {"vzsock_ssh_srv", NULL};
	void *conn;
	int debug = LOG_DEBUG;
	char buffer[BUFSIZ]; 
	char * const targs[] = { "/bin/tar", "-c", "-S", "--ignore-failed-read", "--numeric-owner", "-f", "-", "-C", "/root/", "vzmigrate", NULL };

	if (argc != 3) {
		fprintf(stderr, "Usage : %s path hostname\n", argv[0]);
		return 1;
	}
	path = (char *)argv[1];

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
	if ((rc = vzsock_send(&ctx, conn, CMD_COPY, strlen(CMD_COPY)+1))) {
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

	return 0;
}
