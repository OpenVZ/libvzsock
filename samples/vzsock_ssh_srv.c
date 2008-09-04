#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libvzsock.h>
#include <string.h>
#include <syslog.h>

//int logger(int level, const char *fmt, va_list pvar);
//int readpwd(const char *prompt, char *pass, size_t size);

int main(int argc, const char *argv[])
{
	int rc;
	struct vzsock_ctx ctx;
	int debug = LOG_DEBUG;
	char * const args[] = {NULL};
	void *conn;
	char cmd[BUFSIZ];
	int fds[2];
	const char *reply = "|0|reply";

	if ((rc = vzsock_init(VZSOCK_FD, &ctx, NULL, NULL))) {
		syslog(LOG_ERR, "vzsock_init() return %d\n", rc);
		return -1;
	}
	vzsock_set(&ctx, VZSOCK_DATA_DEBUG, (void *)&debug, sizeof(debug));

	if ((rc = vzsock_open(&ctx))) {
		syslog(LOG_ERR, "vzsock_open() return %d\n", rc);
		return -1;
	}

	if ((rc = vzsock_create_conn(&ctx, args, &conn))) {
		syslog(LOG_ERR, "vzsock_create_conn() return %d\n", rc);
		return -1;
	}

	fds[0] = STDIN_FILENO;
	fds[1] = STDOUT_FILENO;
	if ((rc = vzsock_set_conn(&ctx, conn, VZSOCK_DATA_FDPAIR, (void *)fds, sizeof(fds)))) {
		syslog(LOG_ERR, "vzsock_set_conn() return %d\n", rc);
		return -1;
	}
	/* read string, separated by <separator>. Will write '\0' on end of string */
	if ((rc = vzsock_recv_str(&ctx, conn, '\0', cmd, sizeof(cmd)))) {
		syslog(LOG_ERR, "vzsock_recv_str() return %d\n", rc);
		return -1;
	}
	syslog(LOG_INFO, "----> %s\n", cmd);
	if ((rc = vzsock_send(&ctx, conn, reply, strlen(reply)+1))) {
		fprintf(stderr, "vzsock_send() return %d\n", rc);
		return -1;
	}

	vzsock_close_conn(&ctx, conn);
	vzsock_close(&ctx);

	return 0;
}
