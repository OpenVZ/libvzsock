#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>

#include <vz/libvzsock.h>

#include "sample.h"
/*
int logger(int level, const char *fmt, va_list pvar);
{
	char buffer[BUFSIZ];

	snprintf(buffer, sizeof(buffer), "-> %s", cmd);
	syslog(LOG_INFO, "%s", buffer);
	vzsock_send_srv_reply(&ctx, conn, LOG_INFO, buffer);
}
*/

int main(int argc, const char *argv[])
{
	int rc = 0;
	struct vzsock_ctx ctx;
	int debug = LOG_DEBUG;
	void *conn;
	int fds[2];

	openlog("vzs_ssh_srv", LOG_PID, LOG_USER);

	if ((rc = vzsock_init(VZSOCK_FD, &ctx))) {
		syslog(LOG_ERR, "vzsock_init() return %d", rc);
		return -1;
	}
	vzsock_set(&ctx, VZSOCK_DATA_DEBUG, (void *)&debug, sizeof(debug));

	if ((rc = vzsock_open(&ctx))) {
		syslog(LOG_ERR, "vzsock_open() return %d", rc);
		goto cleanup_0;
	}

	if ((rc = vzsock_open_conn(&ctx, NULL, &conn))) {
		syslog(LOG_ERR, "vzsock_create_conn() return %d", rc);
		goto cleanup_0;
	}

	fds[0] = STDIN_FILENO;
	fds[1] = STDOUT_FILENO;
	if ((rc = vzsock_set_conn(&ctx, conn, VZSOCK_DATA_FDPAIR, (void *)fds, sizeof(fds)))) {
		syslog(LOG_ERR, "vzsock_set_conn() return %d", rc);
		goto cleanup_1;
	}

	if ((rc = server(&ctx, conn)))
		goto cleanup_1;

	syslog(LOG_INFO, "Conection closed");

cleanup_1:
	vzsock_close_conn(&ctx, conn);
cleanup_0:
	vzsock_close(&ctx);
	closelog();

	return rc;
}
