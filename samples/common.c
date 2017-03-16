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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>

#include <libvzsock.h>

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
