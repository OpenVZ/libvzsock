#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libvzsock.h>
#include <string.h>
#include <syslog.h>

#include "vzsock_sample.h"

//int logger(int level, const char *fmt, va_list pvar);
//int readpwd(const char *prompt, char *pass, size_t size);

int main(int argc, const char *argv[])
{
	int rc = 0;
	struct vzsock_ctx ctx;
	int debug = LOG_DEBUG;
	char * const args[] = {NULL};
	void *conn;
	char cmd[BUFSIZ];
	int fds[2];

	openlog("vzs_ssh_srv", LOG_PID, LOG_USER);

	if ((rc = vzsock_init(VZSOCK_FD, &ctx, NULL, NULL))) {
		syslog(LOG_ERR, "vzsock_init() return %d", rc);
		return -1;
	}
	vzsock_set(&ctx, VZSOCK_DATA_DEBUG, (void *)&debug, sizeof(debug));

	if ((rc = vzsock_open(&ctx))) {
		syslog(LOG_ERR, "vzsock_open() return %d", rc);
		goto cleanup_0;
	}

	if ((rc = vzsock_create_conn(&ctx, args, &conn))) {
		syslog(LOG_ERR, "vzsock_create_conn() return %d", rc);
		goto cleanup_0;
	}

	fds[0] = STDIN_FILENO;
	fds[1] = STDOUT_FILENO;
	if ((rc = vzsock_set_conn(&ctx, conn, VZSOCK_DATA_FDPAIR, (void *)fds, sizeof(fds)))) {
		syslog(LOG_ERR, "vzsock_set_conn() return %d", rc);
		goto cleanup_1;
	}
	/* read command from client */
	if ((rc = vzsock_recv_str(&ctx, conn, cmd, sizeof(cmd)))) {
		syslog(LOG_ERR, "vzsock_recv_str() return %d", rc);
		goto cleanup_1;
	}

	{
	char buffer[BUFSIZ];

	snprintf(buffer, sizeof(buffer), "-> %s", cmd);
	syslog(LOG_INFO, "%s", buffer);
	vzsock_send_srv_reply(&ctx, conn, LOG_INFO, buffer);
	}

	if (strncmp(cmd, CMD_INIT, strlen(CMD_INIT))) {
		syslog(LOG_ERR, "Invalid command: '%s'", cmd);
		// vzsock_error(&ctx, conn, "Invalid command: '%s'", cmd);
		rc = -1;
		goto cleanup_1;
	}
	syslog(LOG_INFO, "-> %s", cmd);
	if ((rc = vzsock_send_srv_reply(&ctx, conn, 0, CMD_ACK))) {
		syslog(LOG_ERR, "vzsock_send() return %d", rc);
		goto cleanup_1;
	}

	while(1) {
		if ((rc = vzsock_recv_str(&ctx, conn, cmd, sizeof(cmd)))) {
			syslog(LOG_ERR, "vzsock_recv_str() return %d", rc);
			goto cleanup_1;
		}
		if (strlen(cmd) == 0) {
			syslog(LOG_ERR, "Broken channel");
			goto cleanup_1;
		}
		syslog(LOG_INFO, "-> %s", cmd);
		if (strncmp(cmd, CMD_CLOSE, strlen(CMD_CLOSE)) == 0) {
			if ((rc = vzsock_send_srv_reply(&ctx, conn, 0, CMD_ACK))) {
				syslog(LOG_ERR, "vzsock_send() return %d", rc);
				goto cleanup_1;
			}
			break;
		} else if (strncmp(cmd, CMD_COPY, strlen(CMD_CLOSE)) == 0) {
			char * const targs[] = {"tar", "-p", "-S", "--same-owner", "-x", "-C", "/tmp", NULL};
			if ((rc = vzsock_send_srv_reply(&ctx, conn, 0, CMD_ACK))) {
				syslog(LOG_ERR, "vzsock_send_srv_reply() return %d", rc);
				goto cleanup_1;
			}
			if ((rc = vzsock_recv_data(&ctx, conn, targs))) {
				syslog(LOG_ERR, "vzsock_recv_data() return %d", rc);
				goto cleanup_1;
			}
		}
	}
	syslog(LOG_INFO, "Conection closed");

cleanup_1:
	vzsock_close_conn(&ctx, conn);
cleanup_0:
	vzsock_close(&ctx);
	closelog();

	return rc;
}
