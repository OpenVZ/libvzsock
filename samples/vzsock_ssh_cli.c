#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libvzsock.h>
#include <string.h>
#include <syslog.h>

static int logger(int level, const char* fmt, va_list pvar)
{
	FILE *fp = (level <= LOG_WARNING) ? stderr : stdout;
	/* put to syslog and to some output also */
	vsyslog(level, fmt, pvar);
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
	const char *cmd_init = "init";
	int retcode;
	char reply[BUFSIZ]; 

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
		return -1;
	}
	if ((rc = vzsock_open(&ctx))) {
		fprintf(stderr, "vzsock_open() return %d\n", rc);
		return -1;
	}

	if ((rc = vzsock_create_conn(&ctx, args, &conn))) {
		fprintf(stderr, "vzsock_create_conn() return %d\n", rc);
		return -1;
	}
	if ((rc = vzsock_send(&ctx, conn, cmd_init, strlen(cmd_init)+1))) {
		fprintf(stderr, "vzsock_send() return %d\n", rc);
		return -1;
	}
	if ((rc = vzsock_read_srv_reply(&ctx, conn, &retcode, reply, sizeof(reply)))) {
		fprintf(stderr, "vzsock_read_srv_reply() return %d\n", rc);
		return -1;
	}
	fprintf(stdout, "retcode = %d, reply is %s\n", retcode, reply);
	if (retcode) {
		fprintf(stderr, "server side return %d\n", retcode);
		return -1;
	}
	vzsock_close_conn(&ctx, conn);
	vzsock_close(&ctx);

	return 0;
}
