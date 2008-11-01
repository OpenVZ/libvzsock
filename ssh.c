/* $Id: migssh.cpp,v 1.26 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#include <linux/limits.h>
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
#include <time.h>

#include "libvzsock.h"
#include "vzsock.h"
#include "ssh.h"
#include "util.h"

static int test_conn(struct vzsock_ctx *ctx);

static int open_ctx(struct vzsock_ctx *ctx);
static void close_ctx(struct vzsock_ctx *ctx);
/* set context parameter(s) */
static int set_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t size);

static int open_conn(struct vzsock_ctx *ctx, void *data, void **conn);
static int wait_conn(struct vzsock_ctx *ctx, void **conn);
static int accept_conn(struct vzsock_ctx *ctx, void *srv_conn, void **new_conn);
static int close_conn(struct vzsock_ctx *ctx, void *conn);
/* set connection parameter(s) */
static int set_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t size);
static int send(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size);
static int recv_str(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char separator, 
		char *data, 
		size_t size);
static int rcopy(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *task_argv);
static int wait_rcopy(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv);


int _vzs_ssh_init(struct vzsock_ctx *ctx, struct vzs_handlers *handlers)
{
	struct ssh_data *data;

	if ((data = (struct ssh_data *)malloc(sizeof(struct ssh_data))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");

	data->hostname = NULL;
	ctx->type = VZSOCK_SSH;
	ctx->data = (void *)data;

	handlers->open = open_ctx;
	handlers->close = close_ctx;
	handlers->set = set_ctx;
	handlers->open_conn = open_conn;
	handlers->wait_conn = wait_conn;
	handlers->accept_conn = accept_conn;
	handlers->close_conn = close_conn;
	handlers->set_conn = set_conn;
	handlers->send = send;
	handlers->recv_str = recv_str;
	handlers->send_data = rcopy;
	handlers->recv_data = wait_rcopy;

	return 0;
}

/* open context: create test connection */
static int open_ctx(struct vzsock_ctx *ctx)
{
	int rc;

	/* open and close test connection : to get password */
	if ((rc = test_conn(ctx)))
		return rc;

	return 0;
}

static void close_ctx(struct vzsock_ctx *ctx)
{
	struct ssh_data *data = (struct ssh_data *)ctx->data;

	if (data->hostname)
		free(data->hostname);

	free(ctx->data);
	ctx->data = NULL;

	return;
}

/* set context parameter(s) */
static int set_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t size)
{
	struct ssh_data *sshdata = (struct ssh_data *)ctx->data;

	switch (type) {
	case VZSOCK_DATA_HOSTNAME:
	{
		if (sshdata->hostname)
			free(sshdata->hostname);

		if ((sshdata->hostname = malloc(size)) == NULL)
			return _vz_error(ctx, VZS_ERR_SYSTEM, "strdup() : %m");
		memcpy(sshdata->hostname, data, size);
		break;
	}
	default:
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
			"Unknown data type : %d", type);
	}
	return 0;
}

/* get default ssh options
   TODO: customized */
static int get_args(
		struct vzsock_ctx *ctx, 
		struct vzs_string_list *args)
{
	if (_vzs_string_list_add(args, "ssh"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vzs_string_list_add(args, "-T"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vzs_string_list_add(args, "-q"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vzs_string_list_add(args, "-c"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
        /* blowfish is faster then DES3,
           but arcfour is faster then blowfish, according #84995 */
	if (_vzs_string_list_add(args, "arcfour"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vzs_string_list_add(args, "-o"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vzs_string_list_add(args, "StrictHostKeyChecking=no"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vzs_string_list_add(args, "-o"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vzs_string_list_add(args, "CheckHostIP=no"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vzs_string_list_add(args, "-o"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vzs_string_list_add(args, "UserKnownHostsFile=/dev/null"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vzs_string_list_add(args, "-o"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
	if (_vzs_string_list_add(args, 
			"PreferredAuthentications=publickey,password,"\
			"keyboard-interactive"))
		return _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");

	return 0;
}


/* create test ssh connection */
static int test_conn(struct vzsock_ctx *ctx) 
{
	pid_t pid, chpid;
	int rc = 0;
	int status;
	char tmpfile[PATH_MAX + 1];
	char script[PATH_MAX + 1];
	int td, sd;
	FILE *fp;
	struct vzs_string_list ssh_argl;
	char **ssh_argv;
	int i;
	struct ssh_data *data = (struct ssh_data *)ctx->data;

	if (data->hostname == NULL)
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, "hostname does not specified");
	_vzs_string_list_init(&ssh_argl);
	if ((rc = get_args(ctx, &ssh_argl)))
		return rc;
	if (_vzs_string_list_add(&ssh_argl, data->hostname)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_0;
	}
	if (_vzs_string_list_add(&ssh_argl, "true")) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_0;
	}
	if (_vzs_string_list_to_array(&ssh_argl, &ssh_argv)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_0;
	}

	_vzs_show_args(ctx, "establish test ssh channel: ", ssh_argv);

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
		execvp(ssh_argv[0], (char *const *)ssh_argv);
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
				_vzs_read_password(prompt, 
					ctx->password, sizeof(ctx->password));
		}
	} else if (WIFSIGNALED(status)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "Got signal %d", 
				WTERMSIG(status));
		goto cleanup_3;

	} else {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "%s exited with status %d",
				ssh_argv[0], status);
		goto cleanup_3;
	}

cleanup_3:
	unlink(script);
cleanup_2:
	close(td);
	unlink(tmpfile);
cleanup_1:
	for (i = 0; ssh_argv[i]; i++)
		free((void *)ssh_argv[i]);
	free((void *)ssh_argv);
cleanup_0:
	_vzs_string_list_clean(&ssh_argl);

	return rc;
}

/* create ASKPASS file for ssh */
static int generate_askpass(
		struct vzsock_ctx *ctx, 
		char *path, 
		size_t size)
{
	int fd;
	FILE *fp;
	const char *p;

	path[0] = '\0';
	if (ctx->password == NULL)
		return 0;

	if (strlen(ctx->password) == 0)
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
	for (p = ctx->password; *p; p++) {
		if (strchr("\\\"$`", *p))
			fputc('\\', fp);
		fputc(*p, fp);
	}
	fprintf(fp, "\"\nrm -f \"%s\"\n", path);
	fclose(fp);
	chmod(path, S_IRUSR|S_IXUSR);

	return 0;
}

/* open new connection */
static int open_conn(struct vzsock_ctx *ctx, void *arg, void **conn)
{
	int rc = 0;
	pid_t pid, ssh_pid;
	int in[2], out[2];
	int status;
	struct ssh_conn *cn;
	struct vzs_string_list ssh_argl;
	char **ssh_argv;
	int i;
	struct ssh_data *data = (struct ssh_data *)ctx->data;
	char **args = (char **)arg;

	if ((cn = (struct ssh_conn *)malloc(sizeof(struct ssh_conn))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");
	cn->askfile[0] = '\0';
	cn->in = -1;
	cn->out = -1;
	cn->pid = 0;
	*conn = cn;

	_vzs_string_list_init(&ssh_argl);
	if ((rc = get_args(ctx, &ssh_argl)))
		return rc;
	if (_vzs_string_list_add(&ssh_argl, data->hostname)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_0;
	}
	for (i = 0; args[i]; i++) {
		if (_vzs_string_list_add(&ssh_argl, args[i])) {
			rc = _vz_error(ctx, 
				VZS_ERR_SYSTEM, "memory alloc : %m");
			goto cleanup_0;
		}
	}
	if (_vzs_string_list_to_array(&ssh_argl, &ssh_argv)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_0;
	}

	_vzs_show_args(ctx, "establish ssh channel: ", ssh_argv);

	/* if password is needs, create askpass file */
	if ((rc = generate_askpass(ctx, cn->askfile, sizeof(cn->askfile))))
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
/*
		struct rlimit flim;
		unsigned int fdmax, fd;
		if (getrlimit(RLIMIT_NOFILE, &flim) == -1)
			fdmax = OPEN_MAX;
		else
			fdmax = flim.rlim_max;
		for(fd = STDERR_FILENO+1; fd < fdmax; fd++)
			close(fd);
*/
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
		execvp(ssh_argv[0], ssh_argv);
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
	for (i = 0; ssh_argv[i]; i++)
		free((void *)ssh_argv[i]);
	free((void *)ssh_argv);
cleanup_0:
	_vzs_string_list_clean(&ssh_argl);

	return rc;
}

static int wait_conn(struct vzsock_ctx *ctx, void **conn)
{
	return -1;
}

static int accept_conn(struct vzsock_ctx *ctx, void *srv_conn, void **new_conn)
{
	return -1;
}

static int close_conn(struct vzsock_ctx *ctx, void *conn)
{
	struct ssh_conn *cn = (struct ssh_conn *)conn;

	if (cn->pid != 0) {
/* TODO: check retcode and SIGKILL ? */
		kill(cn->pid, SIGTERM);
		cn->pid = 0;
	}

	return 0;
}

/* set connection parameter(s) */
static int set_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t size)
{
	struct ssh_conn *cn = (struct ssh_conn *)conn;

	switch (type) {
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

static int send(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size)
{
	struct ssh_conn *cn = (struct ssh_conn *)conn;

	return _vzs_writefd(ctx, cn->out, data, size, 0);
}

/* 
  read from nonblocking descriptor <fd> string, separated by <separator>.
  will write '\0' on the end of string
*/
static int recv_str(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char separator, 
		char *data, 
		size_t size)
{
	struct ssh_conn *cn = (struct ssh_conn *)conn;

	return _vzs_recv_str(ctx, cn->in, separator, data, size);
}

/* File/directory copy
   we cannot use existing connection (tar server will wait stdin closing)
   all operations will complete from client side
   server part can not wait infinitely
   we can not define any timeout value for server part
   Client:
   - create new ssh connection with server and run ssh on dst
   - 
   - on dst side server should wait tar
  save tar pid on file


   - run ssh with tar on src
   - wait tar exiting on dst */

static int wait_rcopy(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char * const *argv)
{
	return 0;
}

/* use control connection to info exchange
   run local task, create new ssh connection to server with <remote_cmd>, 
   redirect stdin and stdout of local task to ssh channel
*/
static int _remote_rcopy(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * remote_cmd,
		const char * sync_msg,
		char * const *task_argv)
{
	int rc = 0;
	pid_t ssh_pid = -1, task_pid = -1, pid;
	int status;
	char askpath[PATH_MAX];
	int in[2], out[2];
	struct vzs_string_list ssh_argl;
	char **ssh_argv;
	struct ssh_data *data = (struct ssh_data *)ctx->data;
	int i;

	_vzs_string_list_init(&ssh_argl);

	/* if password is needs, create askpass file */
	if ((rc = generate_askpass(ctx, askpath, sizeof(askpath))))
		return rc;

	if ((pipe(in) < 0) || (pipe(out) < 0)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "pipe() error, %m");
		goto cleanup_0;
	}
	_vz_set_nonblock(out[0]);

	if ((rc = get_args(ctx, &ssh_argl))) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_1;
	}
	if (_vzs_string_list_add(&ssh_argl, data->hostname)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_1;
	}
	if (_vzs_string_list_add(&ssh_argl, remote_cmd)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_1;
	}
	if (_vzs_string_list_to_array(&ssh_argl, &ssh_argv)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "memory alloc : %m");
		goto cleanup_1;
	}

	 _vzs_show_args(ctx, "establish ssh channel: ", ssh_argv);

	ssh_pid = fork();
	if (ssh_pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_2;
	} else if (ssh_pid == 0) {
		int fd;
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		/* redirect stdout to out and stdin to in */
		close(STDIN_FILENO); close(STDOUT_FILENO);
		close(in[1]); close(out[0]);
		dup2(in[0], STDIN_FILENO);
		dup2(out[1], STDOUT_FILENO);
		if ((fd = open("/dev/null", O_WRONLY)) != -1) {
			close(STDERR_FILENO);
			dup2(fd, STDERR_FILENO);
		}
		close(in[0]); close(out[1]);
		if (strlen(askpath)) {
			setenv("DISPLAY", "dummy", 0);
			setenv("SSH_ASKPASS", askpath, 1);
		}
		setsid();
		execvp(ssh_argv[0], (char *const *)ssh_argv);
		exit(VZS_ERR_SYSTEM);
	}
	close(in[0]); close(out[1]);
	while ((pid = waitpid(ssh_pid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "waitpid() error: %m");
		goto cleanup_3;
	}

	 _vzs_show_args(ctx, "run local task", task_argv);

	task_pid = fork();
	if (task_pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_3;
	} else if (task_pid == 0) {
		int fd;
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		/* redirect stdout to out and stdin to in */
		close(STDOUT_FILENO); close(STDIN_FILENO);
		dup2(in[1], STDOUT_FILENO);
		dup2(out[0], STDIN_FILENO);
		if ((fd = open("/dev/null", O_WRONLY)) != -1) {
			close(STDERR_FILENO);
			dup2(fd, STDERR_FILENO);
		}
		close(in[1]); close(out[0]);
		execvp(task_argv[0], (char *const *)task_argv);
		exit(VZS_ERR_SYSTEM);
	}
	close(in[1]); close(out[0]);

	if ((rc = send(ctx, conn, sync_msg, strlen(sync_msg) + 1)))
		goto cleanup_4;

	rc = 0;
	while (1) {
		while ((pid = waitpid(-1, &status, 0)) == -1)
			if (errno != EINTR)
				break;
		if (pid < 0) {
			rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
			goto cleanup_4;
		}

		if (pid == ssh_pid) {
			ssh_pid = -1;
			if ((rc = _vzs_check_exit_status(ctx, (char *)ssh_argv[0], status))) {
				/* remote task failed or signaled, send SIGTERM to 
				local task and exit immediately */
				goto cleanup_4;
			}
			if (task_pid == -1)
				break;
		} else if (pid == task_pid) {
			task_pid = -1;
			if ((rc = _vzs_check_exit_status(ctx, (char *)task_argv[0], status))) {
				/* local task failed or signaled, send SIGTERM to 
				remote task and exit immediately */
				goto cleanup_4;
			}
			if (ssh_pid == -1)
				break;
		}
	}
cleanup_4:
	if (task_pid >= 0)
		kill(task_pid, SIGTERM);
cleanup_3:
	if (ssh_pid >= 0)
		kill(ssh_pid, SIGTERM);
cleanup_2:
	for (i = 0; ssh_argv[i]; i++)
		free((void *)ssh_argv[i]);
	free((void *)ssh_argv);
cleanup_1:
	close(in[0]); close(out[1]);
	close(in[1]); close(out[0]);
cleanup_0:
	if (strlen(askpath))
		unlink(askpath);

	_vzs_string_list_clean(&ssh_argl);

	return rc;
}

/* remote copy */
static int rcopy(struct vzsock_ctx *ctx, void *conn, char * const *argv)
{
	int rc;
	char reply[BUFSIZ];

	/* read remote command from server */
	if ((rc = vzsock_read_srv_reply(ctx, conn, reply, sizeof(reply))))
		return rc;

	if ((rc = _remote_rcopy(ctx, conn, reply, VZS_SYNC_MSG, argv)))
		return rc;

	/* and wait acknowledgement */
	if ((rc = vzsock_read_srv_reply(ctx, conn, reply, sizeof(reply))))
		return rc;
	return 0;
}
#if 0
/* remote copy, old vzmigrate mode */
static int old_rcopy(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * pid_file,
		const char * remote_cmd,
		char * const *argv)
{
	int rc;
	char reply[PATH_MAX];
	char buffer[BUFSIZ];

	/* read reply from server with target path */
	if ((rc = vzsock_read_srv_reply(ctx, conn, reply, sizeof(reply))))
		return 0;
	snprintf(buffer, sizeof(buffer),
		"echo $$ > %s/%s; tar -p -S --same-owner -x -C %s",
		reply, pid_file, reply);

	return _remote_rcopy(ctx, conn, remote_cmd, "ssh_started", argv);
}
#endif

