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

int server(struct vzsock_ctx *ctx, void *sock)
{
	int rc = 0;
	char cmd[BUFSIZ];
	char path[PATH_MAX];
	char * const targs[] = {
			"tar", 
			"-p", 
			"-S", 
			"--same-owner", 
			"-x", 
			"-C", 
			path, 
			NULL};
	char *p;
	void *conn;
	size_t size;

	if ((rc = vzsock_accept_conn(ctx, sock, &conn))) {
		syslog(LOG_ERR, "vzsock_accept_conn() return %d", rc);
		return rc;
	}

	/* read command from client */
	size = sizeof(cmd);
	if ((rc = vzsock_recv_str(ctx, conn, cmd, &size))) {
		syslog(LOG_ERR, "vzsock_recv_str() return %d", rc);
		return rc;
	}

	if (strncmp(cmd, CMD_INIT, strlen(CMD_INIT))) {
		syslog(LOG_ERR, "Invalid command: '%s'", cmd);
		// vzsock_error(&ctx, conn, "Invalid command: '%s'", cmd);
		return -1;
	}
	/* send acknowledgement */
	if ((rc = vzsock_send(ctx, conn, CMD_ACK, strlen(CMD_ACK)+1))) {
		syslog(LOG_ERR, "vzsock_send() return %d", rc);
		return rc;
	}

	while(1) {
		size = sizeof(cmd);
		if ((rc = vzsock_recv_str(ctx, conn, cmd, &size))) {
			syslog(LOG_ERR, "vzsock_recv_str() return %d", rc);
			return rc;
		}
		if (strlen(cmd) == 0) {
			syslog(LOG_ERR, "Broken channel");
			return rc;
		}
		if (strncmp(cmd, CMD_CLOSE, strlen(CMD_CLOSE)) == 0) {
			if ((rc = vzsock_send(ctx, conn, CMD_ACK, strlen(CMD_ACK)+1))) {
				syslog(LOG_ERR, "vzsock_send() return %d", rc);
				return rc;
			}
			break;
		} else if (strncmp(cmd, CMD_COPY, strlen(CMD_COPY)) == 0) {
			if ((rc = vzsock_send(ctx, conn, CMD_ACK, strlen(CMD_ACK)+1))) {
				syslog(LOG_ERR, "vzsock_send() return %d", rc);
				return rc;
			}
			/* get target path from command */
			p = cmd + strlen(CMD_COPY);
			while (*p == ' ') p++;
			strncpy(path, p, sizeof(path));
			if ((rc = vzsock_recv_data(ctx, conn, targs))) {
				syslog(LOG_ERR, "vzsock_recv_data() return %d", rc);
				return rc;
			}
		} else {
			if ((rc = vzsock_send(ctx, conn, 
					CMD_REJECT, strlen(CMD_REJECT)+1)))
			{
				syslog(LOG_ERR, "vzsock_send() return %d", rc);
				return rc;
			}
		}
	}

	return 0;
}
