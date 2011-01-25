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
#include <sys/time.h>
#include <sys/resource.h>

#include "libvzsock.h"
#include "vzsock.h"
#include "ssh.h"
#include "util.h"

static int test_conn(struct vzsock_ctx *ctx);

static int open_ctx(struct vzsock_ctx *ctx);
static void close_ctx(struct vzsock_ctx *ctx);
/* set context parameter(s) */
static int set_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t size);
static int get_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t *size);

static int open_conn(struct vzsock_ctx *ctx, void *data, void **conn);
static int accept_conn(struct vzsock_ctx *ctx, void *srv_conn, void **new_conn);
static int is_open_conn(void *conn);
static int close_conn(struct vzsock_ctx *ctx, void *conn);
/* set connection parameter(s) */
static int set_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t size);
static int get_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t *size);
static int send(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size);
static int send_err_msg(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size);
static int recv_str(
		struct vzsock_ctx *ctx, 
		void *conn, 
		char separator, 
		char *data, 
		size_t *size);
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
	_vzs_string_list_init(&data->args);
	ctx->type = VZSOCK_SSH;
	ctx->data = (void *)data;

	handlers->open = open_ctx;
	handlers->close = close_ctx;
	handlers->set = set_ctx;
	handlers->get = get_ctx;
	handlers->open_conn = open_conn;
	handlers->accept_conn = accept_conn;
	handlers->is_open_conn = is_open_conn;
	handlers->close_conn = close_conn;
	handlers->set_conn = set_conn;
	handlers->get_conn = get_conn;
	handlers->send = send;
	handlers->send_err_msg = send_err_msg;
	handlers->recv_str = recv_str;
	handlers->send_data = rcopy;
	handlers->recv_data = wait_rcopy;

	return 0;
}

/* open context: create test connection */
static int open_ctx(struct vzsock_ctx *ctx)
{
	struct ssh_data *data = (struct ssh_data *)ctx->data;

	if (data->hostname == NULL)
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
			"hostname does not specified");

	/* check password via test connection */
	return test_conn(ctx);
}

static void close_ctx(struct vzsock_ctx *ctx)
{
	struct ssh_data *data = (struct ssh_data *)ctx->data;

	_vzs_string_list_clean(&data->args);
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
		if (sshdata->hostname)
			free(sshdata->hostname);

		if ((sshdata->hostname = malloc(size)) == NULL)
			return _vz_error(ctx, VZS_ERR_SYSTEM, "strdup() : %m");
		memcpy(sshdata->hostname, data, size);
		break;
	case VZSOCK_DATA_ARGS:
		_vzs_string_list_clean(&sshdata->args);
		return _vzs_string_list_from_array(&sshdata->args, (char **)data);
	default:
		return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
			"Unknown data type : %d", type);
	}
	return 0;
}

/* get context parameter(s) */
static int get_ctx(struct vzsock_ctx *ctx, int type, void *data, size_t *size)
{
	return _vz_error(ctx, VZS_ERR_BAD_PARAM, "Unknown data type : %d", type);
}

/* get full ssh command line : ssh <data->args...> <data->hostname> <cmd...> */
static int get_args(struct vzsock_ctx *ctx, char **cmd, char ***a)
{
	struct ssh_data *data = (struct ssh_data *)ctx->data;
	struct vzs_string_list_el *p;
	size_t lsz, csz, i;

	lsz = _vzs_string_list_size(&data->args);
	for (csz = 0; cmd[csz]; csz++) ; 

	if ((*a = (char **)calloc(1 + lsz + 1 + csz + 1, 
			sizeof(char *))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "calloc() : %m");

	if (((*a)[0] = strdup("ssh")) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "strdup() : %m");

	for (p = data->args.tqh_first, i = 1; p; p = p->e.tqe_next, i++) 
		if (((*a)[i] = strdup(p->s)) == NULL)
			return _vz_error(ctx, VZS_ERR_SYSTEM, "strdup() : %m");

	if (((*a)[lsz+1] = strdup(data->hostname)) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "strdup() : %m");

	for (i = 0; cmd[i]; i++)
		if (((*a)[i+lsz+2] = strdup(cmd[i])) == NULL)
			return _vz_error(ctx, VZS_ERR_SYSTEM, "strdup() : %m");

	(*a)[lsz+2+csz] = NULL;

	return 0;
}

/* So one context can open many connections, it's needs to know ssh password.
   To get get password will use askpass script. This script will interact 
   with this function via fifo.
   Since ssh will not call this script if find public key in authorized_keys file,
   and  open() on fifo will lock, call open() from separate task */ 
static int test_conn(struct vzsock_ctx *ctx) 
{
	int rc = 0;
	int status;
	pid_t pid, fpid, chpid;
	fd_set fds;
	char buffer[BUFSIZ];
	int fd, sd;
	FILE *sp;
	int in[2], out[2], sig[2];
	int fdmax;
	int i;

	char script[PATH_MAX+1];
	char ififo[PATH_MAX+1];
	char ofifo[PATH_MAX+1];

	char *cmd[] = { "true", NULL };
	char **argv;

	if ((rc = get_args(ctx, cmd, &argv)))
		return rc;

	_vzs_show_args(ctx, "", argv);

	/* create input fifo */
	snprintf(ififo, sizeof(ififo), "%s/ififo.XXXXXX", ctx->tmpdir);
	if ((fd = mkstemp(ififo)) == -1) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "mkstemp(%s) : %m", ififo);
		goto cleanup_1;
	}
	close(fd);
	unlink(ififo);
	if (mkfifo(ififo, S_IRUSR|S_IWUSR) < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "mkfifo(%s) : %m", ififo);
		goto cleanup_1;
	}

	/* create output fifo */
	snprintf(ofifo, sizeof(ofifo), "%s/ofifo.XXXXXX", ctx->tmpdir);
	if ((fd = mkstemp(ofifo)) == -1) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "mkstemp(%s) : %m", ofifo);
		goto cleanup_2;
	}
	close(fd);
	unlink(ofifo);
	if (mkfifo(ofifo, S_IRUSR|S_IWUSR) < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "mkfifo(%s) : %m", ofifo);
		goto cleanup_2;
	}

	/* create script */
	snprintf(script, sizeof(script), "%s/script.XXXXXX", ctx->tmpdir);
	if ((sd = mkstemp(script)) == -1) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "mkstemp(%s) : %m", script);
		goto cleanup_3;
	}
	if ((sp = fdopen(sd, "w")) == NULL) {
		close(sd);
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fdopen(%s) : %m", script);
		goto cleanup_3;
	}
	fprintf(sp, "#!/bin/sh\necho -n $@ >> %s\n", ififo);
	fprintf(sp, "cat %s\n", ofifo);
	fclose(sp);
	close(sd);
	chmod(script, S_IRUSR|S_IXUSR);

	if ((pipe(in) < 0) || (pipe(out) < 0) || (pipe(sig) < 0)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "pipe() : %m");
		goto cleanup_4;
	}

	fpid = fork();
	if (fpid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_5;
	} else if (fpid == 0) {
		size_t size;
		int ifd, ofd;

		close(in[0]); close(out[1]);
		close(sig[0]); close(sig[1]);
		while (1) {
		if ((ifd = open(ififo, O_RDONLY)) < 0) {
			_vz_error(ctx, VZS_ERR_SYSTEM, "open() : %m");
			exit(-1);
		}
		if ((size = read(ifd, buffer, sizeof(buffer))) < 0) {
			_vz_error(ctx, VZS_ERR_SYSTEM, "read() : %m");
			exit(-1);
		}
		close(ifd);
		if (write(in[1], buffer, size) < 0) {
			_vz_error(ctx, VZS_ERR_SYSTEM, "write() : %m");
			exit(-1);
		}

		if ((size = read(out[0], buffer, sizeof(buffer))) < 0) {
			_vz_error(ctx, VZS_ERR_SYSTEM, "read() : %m");
			exit(-1);
		}
		if ((ofd = open(ofifo, O_WRONLY)) < 0) {
			_vz_error(ctx, VZS_ERR_SYSTEM, "open() : %m");
			exit(-1);
		}
		if (write(ofd, buffer, size) < 0) {
			_vz_error(ctx, VZS_ERR_SYSTEM, "write() : %m");
			exit(-1);
		}
		close(ofd);
		}
		exit(0);
	}

	chpid = fork();
	if (chpid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_6;
	} else if (chpid == 0) {
		int nfd;

		close(in[1]); close(out[0]);
		close(in[0]); close(out[1]);
		close(sig[0]);
		nfd = open("/dev/null", O_RDWR);
		dup2(nfd, STDIN_FILENO);
		dup2(nfd, STDOUT_FILENO);
		dup2(nfd, STDERR_FILENO);
		close(nfd);
		setenv("DISPLAY", "dummy", 0);
		setenv("SSH_ASKPASS", script, 1);
		setsid();
		execvp(argv[0], (char *const *)argv);
		exit(VZS_ERR_SYSTEM);
	}
	close(in[1]); close(out[0]);
	close(sig[1]);

	while ((pid = waitpid(fpid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "waitpid() : %m");
		goto cleanup_7;
	}

	do {
		FD_ZERO(&fds);
		FD_SET(in[0], &fds);
		FD_SET(sig[0], &fds);
		fdmax = (in[0] > sig[0]) ? in[0] : sig[0];
		if (select(fdmax + 1, &fds, NULL, NULL, NULL) < 0) {
			rc = _vz_error(ctx, VZS_ERR_SYSTEM, "select() : %m");
			goto cleanup_7;
		}
		if (FD_ISSET(in[0], &fds)) {
			if (read(in[0], buffer, sizeof(buffer)) < 0) {
				rc = _vz_error(ctx, 
					VZS_ERR_SYSTEM, "read() : %m");
				goto cleanup_7;
			}
			if (!ctx->lpassword) {
				_vzs_read_password(buffer, 
					ctx->password, sizeof(ctx->password));
			}
			if (write(out[1], ctx->password, 
					strlen(ctx->password)+1) < 0)
			{
				rc = _vz_error(ctx, 
					VZS_ERR_SYSTEM, "write() : %m");
				goto cleanup_7;
			}
//			break;
		} else if (FD_ISSET(sig[0], &fds)) {
			/* main task completed without askpass */
			break;
		}
	} while (1);

	while ((pid = waitpid(chpid, &status, 0)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "waitpid() : %m");
		goto cleanup_6;
	}

	rc = _vzs_check_exit_status(ctx, argv[0], status);
	goto cleanup_6;

cleanup_7:
	kill(chpid, SIGTERM);
cleanup_6:
	kill(fpid, SIGTERM);
cleanup_5:
	close(in[0]); close(in[1]);
	close(out[0]); close(out[1]);
	close(sig[0]); close(sig[1]);
cleanup_4:
	unlink(script);
cleanup_3:
	unlink(ofifo);
cleanup_2:
	unlink(ififo);
cleanup_1:
	for (i = 0; argv[i]; i++)
		free((void *)argv[i]);
	free((void *)argv);

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

	if (strlen(ctx->password) == 0)
		return 0;

	path[0] = '\0';

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
	char **argv;
	int i;
	char **cmd = (char **)arg;

	if ((cn = (struct ssh_conn *)malloc(sizeof(struct ssh_conn))) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, "malloc() : %m");
	cn->askfile[0] = '\0';
	cn->in = -1;
	cn->out = -1;
	cn->pid = 0;
	*conn = cn;

	if ((rc = get_args(ctx, cmd, &argv)))
		goto cleanup_0;

	_vzs_show_args(ctx, "", argv);

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
		/* redirect stdout to out and stdin to in */
		close(in[1]); close(out[0]);
		dup2(in[0], STDIN_FILENO);
		dup2(out[1], STDOUT_FILENO);
/*
		Will not redirect stderr into out:
		ssh halt if can not write on stderr and it's possible
		that parent process not read from out in this time.
		dup2(out[1], STDERR_FILENO);
*/
		/* to close all unused descriptors */
		int fdnum;
		struct rlimit rlim;
		if (getrlimit(RLIMIT_NOFILE, &rlim) == 0)
			fdnum = (int)rlim.rlim_cur;
		else
			fdnum = 1024;
		for (i = 3; i < fdnum; ++i)
			close(i);
		setenv("DISPLAY", "dummy", 0);
		setenv("SSH_ASKPASS", cn->askfile, 1);
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

	for (i = 0; argv[i]; i++)
		free((void *)argv[i]);
	free((void *)argv);
	return 0;

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
	free((void *)cn);

	return rc;
}

static int accept_conn(struct vzsock_ctx *ctx, void *srv_conn, void **new_conn)
{
	return -1;
}

static int is_open_conn(void *conn)
{
	struct ssh_conn *cn = (struct ssh_conn *)conn;

	if (conn == NULL)
		return 0;
	if (cn->pid == 0)
		return 0;
	if (kill(cn->pid, 0))
		return 0;

	return 1;
}

static int close_conn(struct vzsock_ctx *ctx, void *conn)
{
	struct ssh_conn *cn = (struct ssh_conn *)conn;

	if (!is_open_conn(conn))
		return 0;

/* TODO: check retcode and SIGKILL ? */
	kill(cn->pid, SIGTERM);
	free(conn);

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

/* get connection parameter(s) */
static int get_conn(struct vzsock_ctx *ctx, void *conn, 
		int type, void *data, size_t *size)
{
	struct ssh_conn *cn = (struct ssh_conn *)conn;

	switch (type) {
	case VZSOCK_DATA_FDPAIR:
	{
		/* get pair of descriptors */
		int fd[2];

		if (*size < sizeof(fd))
			return _vz_error(ctx, VZS_ERR_BAD_PARAM, 
				"It is't enough buffer size (%d) "\
				"for data type : %d", *size, type);
		fd[0] = cn->in;
		fd[1] = cn->out;
		memcpy(data, (void *)fd, sizeof(fd));
		*size = sizeof(fd);
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

static int send_err_msg(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size)
{
	struct ssh_conn *cn = (struct ssh_conn *)conn;

	return _vzs_writefd(ctx, cn->out, data, size, 1);
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
		size_t *size)
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
		char **cmd,
		const char * sync_msg,
		char * const *task_argv)
{
	int rc = 0;
	pid_t ssh_pid = -1, task_pid = -1, pid;
	int status;
	char askpath[PATH_MAX];
	int in[2], out[2];
	char **ssh_argv;
	int i;

	/* if password is needs, create askpass file */
	askpath[0] = '\0';
	if ((rc = generate_askpass(ctx, askpath, sizeof(askpath))))
		return rc;

	if ((pipe(in) < 0) || (pipe(out) < 0)) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "pipe() error, %m");
		goto cleanup_0;
	}
	_vz_set_nonblock(out[0]);

	if ((rc = get_args(ctx, cmd, &ssh_argv)))
		goto cleanup_1;

	 _vzs_show_args(ctx, "", ssh_argv);

	ssh_pid = fork();
	if (ssh_pid < 0) {
		rc = _vz_error(ctx, VZS_ERR_SYSTEM, "fork() : %m");
		goto cleanup_2;
	} else if (ssh_pid == 0) {
		int fd;
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		/* redirect stdout to out and stdin to in */
		close(in[1]); close(out[0]);
		dup2(in[0], STDIN_FILENO);
		dup2(out[1], STDOUT_FILENO);
		if ((fd = open("/dev/null", O_WRONLY)) != -1) {
			close(STDERR_FILENO);
			dup2(fd, STDERR_FILENO);
		}
		close(in[0]); close(out[1]);
		setenv("DISPLAY", "dummy", 0);
		setenv("SSH_ASKPASS", askpath, 1);
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

	 _vzs_show_args(ctx, "", task_argv);

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

	return rc;
}

/* remote copy */
static int rcopy(struct vzsock_ctx *ctx, void *conn, char * const *argv)
{
	int rc;
	char reply[BUFSIZ];
	char *args[] = { reply, NULL };
	size_t size;

	/* read remote command from server */
	size = sizeof(reply);
	if ((rc = vzsock_recv_str(ctx, conn, reply, &size)))
		return rc;

	if ((rc = _remote_rcopy(ctx, conn, args, VZS_SYNC_MSG, argv)))
		return rc;

	/* and wait acknowledgement */
	size = sizeof(reply);
	if ((rc = vzsock_recv_str(ctx, conn, reply, &size)))
		return rc;
	return 0;
}

