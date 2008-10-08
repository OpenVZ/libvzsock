/*
 *
 * Copyright (c) Parallels, 2008
 *
 */

#ifndef __VZSOCK_SAMPLE_H__
#define __VZSOCK_SAMPLE_H__

#define CMD_INIT "init"
#define CMD_CLOSE "close"
#define CMD_ACK "ack"
#define CMD_COPY "copy"
#define CMD_REJECT "reject"

#define VZSOCK_TEST_PORT 4422

int server(struct vzsock_ctx *ctx, void *conn);

#endif
