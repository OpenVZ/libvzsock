/* $Id: migssh.cpp,v 1.26 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#include <limits.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "libvzsock.h"
#include "util.h"
#include "ssh.h"
#include "sock.h"


int vzsock_init(
		int type, 
		struct vzsock *vzs,
		int (*logger)(int level, const char *fmt, va_list pvar),
		int (*readpwd)(const char *prompt, char *pass, size_t size))
{
	int rc;
	char path[PATH_MAX];

/* TODO : ident */
	openlog("VZM", LOG_PERROR, LOG_USER);

	vzs->clean = NULL;
	vzs->test_conn = NULL;
	vzs->create_main_conn = NULL;
	vzs->set = NULL;
/*
	vzs->recv_str = NULL;
	vzs->send = NULL;
	vzs->close = NULL;
	vzs->is_connected = NULL;
*/

	/* init context */
	vzs->ctx.conn = NULL;
	vzs->ctx.debug = 0;
	vzs->ctx.errcode = 0;
	vzs->ctx.errmsg[0] = '\0';
	vzs->ctx.logger = logger;
	vzs->ctx.readpwd = readpwd;
	vzs->ctx.password[0] = '\0';

	/* create temporary directory (mkdtemp() will set perms 0700) */
	if (_vz_get_tmp_dir(path, sizeof(path)))
		path[0] = '\0';
	snprintf(vzs->ctx.tmpdir, 
		sizeof(vzs->ctx.tmpdir), "%s/vzm.XXXXXX", path);
	if (mkdtemp(vzs->ctx.tmpdir) == NULL)
		return _vz_error(&vzs->ctx, VZS_ERR_SYSTEM,
			"mkdtemp(%s) : %m", vzs->ctx.tmpdir);

	switch (type) {
	case VZSOCK_SOCK:
		if ((rc = _vz_sock_init(vzs)))
			goto cleanup_0;
		break;
	case VZSOCK_SSH:
		if ((rc = _vz_ssh_init(vzs)))
			goto cleanup_0;
		break;
	default:
		rc = _vz_error(&vzs->ctx, VZS_ERR_BAD_PARAM,
			"undefined vzsock type: %d", type);
		goto cleanup_0;
	}

	return 0;

cleanup_0:
	_vz_rmdir(&vzs->ctx, vzs->ctx.tmpdir);

	return rc;
}

int vzsock_set(struct vzsock *vzs, int type, void *data)
{

	switch (type) {
	default:
		return vzs->set(&vzs->ctx, type, data);
	}
	return 0;
}

void vzsock_clean(struct vzsock *vzs)
{
	_vz_rmdir(&vzs->ctx, vzs->ctx.tmpdir);

	vzs->clean(&vzs->ctx);

	closelog();
}

int vzsock_test_conn(struct vzsock *vzs)
{
	return vzs->test_conn(&vzs->ctx);
}

int vzsock_create_main_conn(struct vzsock *vzs, char * const args[])
{
	return vzs->create_main_conn(&vzs->ctx, args);
}
