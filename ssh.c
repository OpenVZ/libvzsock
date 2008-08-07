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
#include <sys/syslog.h>
#include <unistd.h>

#include "libvzsock.h"
#include "ssh.h"
#include "util.h"

static void _vz_ssh_clean(struct vzsock_ctx *ctx);
static int _vz_ssh_test_conn(struct vzsock_ctx *ctx); 
static int _vz_ssh_main_conn(struct vzsock_ctx *ctx, char * const args[]);
static int _vz_ssh_close(struct vzsock_ctx *ctx);
static int _vz_ssh_set(struct vzsock_ctx *ctx, int type, void *data);


int _vz_ssh_init(struct vzsock *vzs)
{
	struct ssh_conn *cn;

	vzs->type = VZSOCK_SSH;
	vzs->clean = _vz_ssh_clean;
	vzs->test_conn = _vz_ssh_test_conn;
	vzs->create_main_conn = _vz_ssh_main_conn;
	vzs->close = _vz_ssh_close;
	vzs->set = _vz_ssh_set;
//	vzs->recv_str = ;
//	vzs->send = ;
//	vzs->close = ;
//	vzs->is_connected = ;

	if ((cn = (struct ssh_conn *)malloc(sizeof(struct ssh_conn))) == NULL)
		return _vz_error(&vzs->ctx, VZS_ERR_SYSTEM, "malloc() : %m");

	cn->askfile[0] = '\0';
	cn->in = -1;
	cn->out = -1;
	cn->pid = 0;
	cn->hostname = NULL;
	vzs->ctx.conn = (void *)cn;

	return 0;
}

static void _vz_ssh_clean(struct vzsock_ctx *ctx)
{
	struct ssh_conn *cn = (struct ssh_conn *)ctx->conn;

	_vz_ssh_close(ctx);

	if (cn->hostname)
		free(cn->hostname);

	free(ctx->conn);
	ctx->conn = NULL;

	return;
}

/* get default ssh options
   TODO: customized */
static int _vz_ssh_get_args(
		struct vzsock_ctx *ctx, 
		struct vz_string_list *args)
{
	if (_vz_string_list_add(args, "ssh"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vz_string_list_add(args, "-T"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vz_string_list_add(args, "-q"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vz_string_list_add(args, "-c"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
        /* blowfish is faster then DES3,
           but arcfour is faster then blowfish, according #84995 */
	if (_vz_string_list_add(args, "arcfour"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vz_string_list_add(args, "-o"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vz_string_list_add(args, "StrictHostKeyChecking=no"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vz_string_list_add(args, "-o"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vz_string_list_add(args, "CheckHostIP=no"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vz_string_list_add(args, "-o"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vz_string_list_add(args, "UserKnownHostsFile=/dev/null"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vz_string_list_add(args, "-o"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vz_string_list_add(args, 
			"PreferredAuthentications=publickey,password,"\
			"keyboard-interactive"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");

	return 0;
}


/* create test ssh connection */
static int _vz_ssh_test_conn(struct vzsock_ctx *ctx) 
{
	pid_t pid, chpid;
	int rc = 0;
	int status;
	char tmpfile[PATH_MAX + 1];
	char script[PATH_MAX + 1];
	int td, sd;
	FILE *fp;
	struct vz_string_list argl;
	char **argv;
	int i;
	struct ssh_conn *cn = (struct ssh_conn *)ctx->conn;

	_vz_string_list_init(&argl);
	if ((rc = _vz_ssh_get_args(ctx, &argl)))
		return rc;
	if (_vz_string_list_add(&argl, cn->hostname)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_0;
	}
	if (_vz_string_list_add(&argl, "true")) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_0;
	}
	if (_vz_string_list_to_array(&argl, &argv)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_0;
	}

	if (ctx->debug) {
		char buffer[BUFSIZ+1];
		buffer[0] = '\0';
		_vz_string_list_to_buf(&argl, buffer, sizeof(buffer));
		_vz_logger(ctx, LOG_DEBUG, 
			"establish test ssh channel: %s", buffer);
	}

	snprintf(tmpfile, sizeof(tmpfile), "%s/tmpfile.XXXXXX", ctx->tmpdir);
	if ((td = mkstemp(tmpfile)) == -1) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "mkstemp(%s) : %m", tmpfile);
		goto cleanup_1;
	}
	/* create script which will write ssh prompt to tmpfile */
	snprintf(script, sizeof(script), "%s/askpass.XXXXXX", ctx->tmpdir);
	if ((sd = mkstemp(script)) == -1) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "mkstemp(%s) : %m", script);
		goto cleanup_2;
	}

	if ((fp = fdopen(sd, "w")) == NULL) {
		close(sd);
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fdopen(%s) : %m", script);
		goto cleanup_2;
	}
	fprintf(fp, "#!/bin/sh\necho \"$@\" > %s\n", tmpfile);
	fclose(fp);
	close(sd);
	chmod(script, S_IRUSR|S_IXUSR);

	chpid = fork();
	if (chpid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_3;
	} else if (chpid == 0) {
		int fd;
		close(td);
		fd = open("/dev/null", O_RDWR);
		close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);
		setenv("DISPLAY", "dummy", 0);
		setenv("SSH_ASKPASS", script, 1);
		setsid();
		execvp(argv[0], (char *const *)argv);
		exit(VZS_ERR_SYSTEM);
	}
	
	while ((pid = waitpid(chpid, &status, 0)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "waitpid() : %m");
		goto cleanup_3;
	}

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status)) {
			/* public key auth failed, trying keyboard-interactive */
			char prompt[BUFSIZ+1];
			ssize_t nr;

			nr = read(td, prompt, sizeof(prompt));
			if (nr < 0) {
				rc = _vz_error(ctx, VZS_ERR_SYSTEM, 
						"read(%s) : %m", tmpfile);
				goto cleanup_3;
			} else if (nr == 0) {
				rc = _vz_error(ctx, VZS_ERR_CANT_CONNECT, 
						"Can't connect");
				goto cleanup_3;
			}
			prompt[nr-1] = '\0';
			if (ctx->readpwd)
				ctx->readpwd(prompt, 
					ctx->password, sizeof(ctx->password));
			else
				_vz_read_password(prompt, 
					ctx->password, sizeof(ctx->password));
		}
	} else if (WIFSIGNALED(status)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "Got signal %d", 
				WTERMSIG(status));
		goto cleanup_3;

	} else {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "%s exited with status %d",
				argv[0], status);
		goto cleanup_3;
	}

cleanup_3:
	unlink(script);
cleanup_2:
	close(td);
	unlink(tmpfile);
cleanup_1:
	for (i = 0; argv[i]; i++)
		free((void *)argv[i]);
	free((void *)argv);
cleanup_0:
	_vz_string_list_clean(&argl);

	return rc;
}

/* create ASKPASS file for ssh */
static int generate_askpass(
		struct vzsock_ctx *ctx, 
		const char *pass, 
		char *path, 
		size_t size)
{
	int fd;
	FILE *fp;
	const char *p;

	path[0] = '\0';
	if (pass == NULL)
		return 0;

	if (strlen(pass) == 0)
		return 0;

	snprintf(path, size, "%s/askpass.XXXXXX", ctx->tmpdir);
	/* mkstemp set perms 0600 (glibc >= 2.0.7)*/
	if ((fd = mkstemp(path)) == -1)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "mkstemp(%s) : %m", path);

	if ((fp = fdopen(fd, "w")) == NULL) {
		close(fd);
		unlink(path);
		return _vz_error(ctx, VZS_ERR_SYSTEM, "fdopen(%s) : %m", path);
	}
	fprintf(fp, "#!/bin/sh\necho \"");
	for (p = pass; *p; p++) {
		if (strchr("\\\"$`", *p))
			fputc('\\', fp);
		fputc(*p, fp);
	}
	fprintf(fp, "\"\nrm -f \"%s\"\n", path);
	fclose(fp);
	chmod(path, S_IRUSR|S_IXUSR);

	return 0;
}

/* start ssh connection */
static int _vz_ssh_main_conn(struct vzsock_ctx *ctx, char * const args[])
{
	int rc = 0;
	pid_t pid, ssh_pid;
	int in[2], out[2];
	int status;
	struct ssh_conn *cn = (struct ssh_conn *)ctx->conn;
	struct vz_string_list argl;
	char **argv;
	int i;

	_vz_string_list_init(&argl);
	if ((rc = _vz_ssh_get_args(ctx, &argl)))
		return rc;
	if (_vz_string_list_add(&argl, cn->hostname)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_0;
	}
	for (i = 0; args[i]; i++) {
		if (_vz_string_list_add(&argl, args[i])) {
			rc = _vz_error(ctx, 
				VZS_ERR_SYSTEM, "memory alloc : %m");
			goto cleanup_0;
		}
	}
	if (_vz_string_list_to_array(&argl, &argv)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_0;
	}

	if (ctx->debug) {
		char buffer[BUFSIZ+1];
		buffer[0] = '\0';
		_vz_string_list_to_buf(&argl, buffer, sizeof(buffer));
		_vz_logger(ctx, LOG_DEBUG, 
			"establish test ssh channel: %s", buffer);
	}

	/* if password is needs, create askpass file */
	if ((rc = generate_askpass(ctx, ctx->password, 
			cn->askfile, sizeof(cn->askfile))))
		goto cleanup_1;

	if ((pipe(in) < 0) || (pipe(out) < 0)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "pipe() : %m");
		goto cleanup_2;
	}
	ssh_pid = fork();
	if (ssh_pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_4;
	} else if (ssh_pid == 0) {
		/* redirect stdout to out and stdin to in */
		close(in[1]); close(out[0]);
		dup2(in[0], STDIN_FILENO);
		dup2(out[1], STDOUT_FILENO);
		dup2(out[1], STDERR_FILENO);
		close(in[0]); close(out[1]);
		if (strlen(cn->askfile)) {
			setenv("DISPLAY", "dummy", 0);
			setenv("SSH_ASKPASS", cn->askfile, 1);
		}
		_vz_set_nonblock(STDOUT_FILENO);
		_vz_set_block(STDIN_FILENO);
		_vz_set_nonblock(STDERR_FILENO);
		setsid();
		execvp(argv[0], argv);
		exit(VZS_ERR_SYSTEM);
	}
	close(in[0]); close(out[1]);
	while ((pid = waitpid(ssh_pid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "waitpid() : %m");
		goto cleanup_3;
	}
	cn->pid = ssh_pid;
	cn->in = out[0];
	cn->out = in[1];
	goto cleanup_1;

cleanup_4:
	close(in[0]); close(out[1]);
cleanup_3:
	close(in[1]); close(out[0]);
cleanup_2:
	if (strlen(cn->askfile))
		unlink(cn->askfile);
cleanup_1:
	for (i = 0; argv[i]; i++)
		free((void *)argv[i]);
	free((void *)argv);
cleanup_0:
	_vz_string_list_clean(&argl);

	return rc;
}

static int _vz_ssh_close(struct vzsock_ctx *ctx)
{
	struct ssh_conn *cn = (struct ssh_conn *)ctx->conn;

	if (cn->pid == 0)
		return 0;
/* TODO: check retcode and SIGKILL ? */
	kill(cn->pid, SIGTERM);
	cn->pid = 0;

	return 0;
}

static int _vz_ssh_set(struct vzsock_ctx *ctx, int type, void *data)
{
	struct ssh_conn *cn = (struct ssh_conn *)ctx->conn;

	switch (type) {
	case VZSOCK_DATA_HOSTNAME:
	{
		if ((cn->hostname = strdup((char *)data)) == NULL)
			return _vz_error(ctx, VZS_ERR_SYSTEM, "strdup() : %m");
		break;
	}
	case VZSOCK_DATA_FDPAIR:
	{
		/* set socket pair */
		int *fd = (int *)data;
		cn->in = fd[0];
		cn->out = fd[1];
		break;
	}
	default:
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
			"Unknown data type : %d", type);
	}
	return 0;
}

