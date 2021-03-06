/*
 * Copyright (c) 2006-2017, Parallels International GmbH
 * Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
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
 * Our contact details: Virtuozzo International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 *
 * queues
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <dirent.h>
#include <linux/unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <termios.h>
#include <syslog.h>
#include <stdarg.h>

#include "util.h"

/* set block/nonblock mode for descriptor <fd>, 
   state==1 - block, otherwise - nonblock */
int __vz_set_block(int fd, int state)
{
        long flags;

        if ((flags = fcntl(fd, F_GETFL)) == -1)
                return -1;

	flags = state ? (flags &~ O_NONBLOCK) : (flags | O_NONBLOCK);
        if ((fcntl(fd, F_SETFL, flags)) == -1)
                return -1;
        return 0;
}

/* set cloexec/noncloexec mode for descriptor <fd>, 
   state==1 - cloexec, otherwise - noncloexec */
int __vz_set_cloexec(int fd, int state)
{
	long flag = state ? FD_CLOEXEC : ~FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flag) == -1)
		return -1;
	return 0;
}

static int __vz_def_logger(int level, const char* fmt, va_list pvar)
{
	/* put to syslog and to some output also */
	vsyslog(level, fmt, pvar);
	return 0;
}

int _vz_def_logger(int level, const char *fmt, ...)
{
	va_list pvar;
	va_start(pvar, fmt);
	__vz_def_logger(level, fmt, pvar);
	va_end(pvar);
	return 0;
}

/* show message */
int _vz_logger(struct vzsock_ctx *ctx, int level, const char *fmt, ...)
{
	va_list pvar;
	va_start(pvar, fmt);
	if (ctx->logger)
		ctx->logger(level, fmt, pvar);
	else
		__vz_def_logger(level, fmt, pvar);
	va_end(pvar);
	return 0;
}

/* put error code and error message in ctx and show error message */
int _vz_error(struct vzsock_ctx *ctx, int errcode, const char * fmt, ...)
{
	va_list ap;
	va_list pvar;
	va_start(ap, fmt);
	va_copy(pvar, ap);
	ctx->errcode = errcode;
	vsnprintf(ctx->errmsg, sizeof(ctx->errmsg), fmt, pvar);
	if (ctx->logger)
		ctx->logger(LOG_ERR, fmt, ap);
	else
		__vz_def_logger(LOG_ERR, fmt, ap);
	va_end(pvar);
	va_end(ap);
	return errcode;
}

/* get temporary directory */
int _vzs_get_tmp_dir(char *path, size_t sz)
{
	int i;
	struct stat st;
	char *tmp_dirs[] = {"/vz/tmp/", "/var/tmp/", "/tmp/", NULL};
	char *tmp;

	/* use TMP envdir if exist */
	if ((tmp = getenv("TMP"))) {
		strncpy(path, tmp, sz);
		if (stat(path, &st) == 0) {
			if (S_ISDIR(st.st_mode)) {
				return 0;
			}
		}
	}
	/* check available tmpdir */
	for (i = 0; tmp_dirs[i]; i++) {
		if (stat(tmp_dirs[i], &st))
			continue;
		if (!S_ISDIR(st.st_mode))
			continue;
		strncpy(path, tmp_dirs[i], sz);
		return 0;
	}
	strncpy(path, "/", sz);
	return 0;
}

/* read password from stdin */
int _vzs_read_password(const char *prompt, char *pass, size_t size)
{
	char ch, *p, *end;
	struct termios term, oterm;
	ssize_t nr;

	write(STDOUT_FILENO, prompt, strlen(prompt)+1);

	if (tcgetattr(STDIN_FILENO, &oterm) == 0) {
		memcpy(&term, &oterm, sizeof(term));
		term.c_lflag &= ~(ECHO | ECHONL);
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);
	}
	end = pass + size - 1;
	for (p = pass; (nr = read(STDIN_FILENO, &ch, 1)) == 1 
			&& ch != '\n' && ch != '\r';) {
		if (p < end)
			*p++ = ch;
	}
	*p = '\0';

	if (memcmp(&term, &oterm, sizeof(term)))
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &oterm);

	write(STDOUT_FILENO, "\n", 1);
	return 0;
}

/* 
 char* double-linked list 
*/
/* add new element in tail */
int _vzs_string_list_add(struct vzs_string_list *ls, const char *str)
{
	struct vzs_string_list_el *p;

	p = (struct vzs_string_list_el *)
		malloc(sizeof(struct vzs_string_list_el));
	if (p == NULL)
		return VZS_ERR_SYSTEM;
	if ((p->s = strdup(str)) == NULL)
		return VZS_ERR_SYSTEM;
	TAILQ_INSERT_TAIL(ls, p, e);

	return 0;
}

/* remove all elements and its content */
void _vzs_string_list_clean(struct vzs_string_list *ls)
{
	struct vzs_string_list_el *el;

	while (ls->tqh_first != NULL) {
		el = ls->tqh_first;
		TAILQ_REMOVE(ls, ls->tqh_first, e);
		free((void *)el->s);
		free((void *)el);
	}
}

/* find string <str> in list <ls> */
struct vzs_string_list_el * _vzs_string_list_find(
		struct vzs_string_list *ls, 
		const char *str)
{
	struct vzs_string_list_el *p;

	if (str == NULL)
		return NULL;

	for (p = ls->tqh_first; p != NULL; p = p->e.tqe_next) {
		if (strcmp(str, p->s) == 0)
			return p;
	}
	return NULL;
}

/* remove element and its content and return pointer to previous elem */
struct vzs_string_list_el * _vzs_string_list_remove(
		struct vzs_string_list *ls,
		struct vzs_string_list_el *el)
{
	/* get previous element */
	struct vzs_string_list_el *prev = *el->e.tqe_prev;

	TAILQ_REMOVE(ls, el, e);
	free((void *)el->s);
	free((void *)el);

	return prev;
}

/* get size of string list <ls> */
size_t _vzs_string_list_size(struct vzs_string_list *ls)
{
	struct vzs_string_list_el *p;
	size_t sz = 0;

	for (p = ls->tqh_first; p != NULL; p = p->e.tqe_next)
		sz++;
	return sz;
}

/* copy string list <ls> to string array <*a> */
int _vzs_string_list_to_array(struct vzs_string_list *ls, char ***a)
{
	struct vzs_string_list_el *p;
	size_t sz, i;

	/* get array size */
	sz = _vzs_string_list_size(ls);
	if ((*a = (char **)calloc(sz + 1, sizeof(char *))) == NULL)
		return VZS_ERR_SYSTEM;
	for (p = ls->tqh_first, i = 0; p != NULL && i < sz; \
				p = p->e.tqe_next, i++) 
	{
		if (((*a)[i] = strdup(p->s)) == NULL)
			return VZS_ERR_SYSTEM;
	}
	(*a)[sz] = NULL;

	return 0;
}

/* copy string array into string list */
int _vzs_string_list_from_array(struct vzs_string_list *ls, char **a)
{
	int rc, i;

	for (i = 0; a[i]; i++)
		if ((rc = _vzs_string_list_add(ls, a[i])))
			return rc;

	return 0;
}

/* copy string list <ls> to <buffer> */
int _vzs_string_list_to_buf(
		struct vzs_string_list *ls, 
		char *buffer, 
		size_t size)
{
	struct vzs_string_list_el *p;

	_vzs_string_list_for_each(ls, p) {
		strncat(buffer, p->s, size-strlen(buffer)-1);
		strncat(buffer, " ", size-strlen(buffer)-1);
	}
	return 0;
}


/* 
 void * double-linked list 
*/
/* add new element in tail */
int _vzs_void_list_add(struct vzs_void_list *ls, const void *ptr)
{
	struct vzs_void_list_el *p;

	p = (struct vzs_void_list_el *)
		malloc(sizeof(struct vzs_void_list_el));
	if (p == NULL)
		return VZS_ERR_SYSTEM;
	p->p = (void *)ptr;
	TAILQ_INSERT_TAIL(ls, p, e);

	return 0;
}

/* remove all elements and its content */
void _vzs_void_list_clean(struct vzs_void_list *ls)
{
	struct vzs_void_list_el *el;

	while (ls->tqh_first != NULL) {
		el = ls->tqh_first;
		TAILQ_REMOVE(ls, ls->tqh_first, e);
		free((void *)el);
	}
}

struct vzs_void_list_el * _vzs_void_list_remove(
		struct vzs_void_list *ls,
		struct vzs_void_list_el *el)
{
	/* get previous element */
	struct vzs_void_list_el *prev = *el->e.tqe_prev;

	TAILQ_REMOVE(ls, el, e);
	free((void *)el);

	return prev;
}




/* remove directory with content */
int _vzs_rmdir(struct vzsock_ctx *ctx, const char *dirname)
{
	char path[PATH_MAX+1];
	DIR * dir;
	struct dirent * de;
	struct stat st;
	int rc = 0;

	if ((dir = opendir(dirname)) == NULL)
		return _vz_error(ctx, VZS_ERR_SYSTEM, 
				"opendir(%s) : %m", dirname);

	while (1) {
		errno = 0;
		if ((de = readdir(dir)) == NULL) {
			if (errno)
				rc = _vz_error(ctx, VZS_ERR_SYSTEM, 
					"readdir(%s) : %m", dirname);
			break;
		}

		if(!strcmp(de->d_name,"."))
			continue;

		if(!strcmp(de->d_name,".."))
			continue;

		snprintf(path, sizeof(path), "%s/%s", dirname, de->d_name);

		if (lstat(path, &st)) {
			rc = _vz_error(ctx, VZS_ERR_SYSTEM, 
					"lstat(%s) : %m", path);
			break;
		}

		if (S_ISDIR(st.st_mode)) {
			if ((rc = _vzs_rmdir(ctx, path)))
				break;
			continue;
		}
		/* remove regfile, symlink, fifo, socket or device */
		if (unlink(path)) {
			rc = _vz_error(ctx, VZS_ERR_SYSTEM, 
					"unlink(%s) : %m", path);
			break;
		}
	}
	closedir(dir);

	/* and remove directory */
	if (rc)
		return rc;

	if (rmdir(dirname))
		return _vz_error(ctx, VZS_ERR_SYSTEM, 
				"rmdir(%s) : %m", dirname);

	return 0;
}

/* Write <size> bytes of <data> in non-blocking descriptor <fd>.
   In <silent> mode do not call _vz_error()/_vz_logger() to avoid recurrent 
   calls on server side. */ 
int _vzs_writefd(
		struct vzsock_ctx *ctx, 
		int fd, 
		const char * data, 
		size_t size,
		int silent)
{
	int rc;
	size_t sent;
	fd_set fds;

	if (size == 0)
		return 0;
	sent = 0;
	while (1) {
		while (1) {
			rc = write(fd, data + sent, (size_t)(size - sent));
			if (rc > 0) {
				sent += rc;
				if (sent >= size)
					return 0;
				continue;
			}
			if (errno == EINTR)
				continue;
			else if (errno == EAGAIN)
				break;
			else {
				if (silent)
					_vz_def_logger(LOG_ERR, "write() : %m");
				else
					_vz_logger(ctx, LOG_ERR, "write() : %m"); 
				return VZS_ERR_CONN_BROKEN;
			}
		}

		/* wait next data in socket */
		do {
			FD_ZERO(&fds);
			FD_SET(fd, &fds);
			if (ctx->tmo) {
				struct timeval tv;
				tv.tv_sec = ctx->tmo;
				tv.tv_usec = 0;
				rc = select(fd + 1, NULL, &fds, NULL, &tv);
			} else {
				rc = select(fd + 1, NULL, &fds, NULL, NULL);
			}
			if (rc == 0) {
				_vz_def_logger(LOG_ERR, 
					"timeout (%d sec)", ctx->tmo);
				return VZS_ERR_TIMEOUT;
			} else if (rc < 0) {
				if (errno == EINTR)
					continue;
				_vz_def_logger(LOG_ERR, "select() : %m");
				return VZS_ERR_SYSTEM;
			}
		} while (!FD_ISSET(fd, &fds));
	}

	/* but we never should be here */
	return VZS_ERR_CONN_BROKEN;
}

/* 
  read from nonblocking descriptor <fd> string, separated by <separator>.
  will write '\0' on the end of string
*/
int _vzs_recv_str(
		struct vzsock_ctx *ctx, 
		int fd, 
		char separator, 
		char *data, 
		size_t *size)
{
	int rc;
	char * p;
	fd_set fds;
	size_t sz = 0;

	p = data;
	*p = '\0';
	while (1) {
		/* read data */
		while (1) {
			errno = 0;
			rc = read(fd, p, 1);
			if (rc > 0) {
				sz += rc;
				if (*p == separator) {
					*p = '\0';
					*size = sz;
					return 0;
				}
				p++;
				if (p >= data + *size)
					return _vz_error(ctx, VZS_ERR_TOOLONG, 
						"recv_str : too long message");
				continue;
			} else if (rc == 0) {
				/* end of file */
				*p = '\0';
				*size = sz;
				return 0;
			}
			if (errno == EINTR)
				continue;
			else if (errno == EAGAIN)
				/* wait next data */
				break;
			else
				return _vz_error(ctx, VZS_ERR_CONN_BROKEN,
					"recv_str : read() : %m");
		}

		/* wait next data in socket */
		do {
			FD_ZERO(&fds);
			FD_SET(fd, &fds);
			if (ctx->tmo) {
				struct timeval tv;
				tv.tv_sec = ctx->tmo;
				tv.tv_usec = 0;
				rc = select(fd + 1, &fds, NULL, NULL, &tv);
			} else {
				rc = select(fd + 1, &fds, NULL, NULL, NULL);
			}
			if (rc == 0)
				return _vz_error(ctx, VZS_ERR_TIMEOUT,
					"recv_str : timeout (%d sec)", ctx->tmo);
			else if (rc < 0) {
				if (errno == EINTR)
					continue;
				return _vz_error(ctx, VZS_ERR_CONN_BROKEN,
					"recv_str : select() : %m");
			}
		} while (!FD_ISSET(fd, &fds));
	}

	/* but we never should be here */
	return VZS_ERR_CONN_BROKEN;
}

int _vzs_check_exit_status(struct vzsock_ctx *ctx, char *task, int status)
{
	int rc;

	if (WIFEXITED(status)) {
		if ((rc = WEXITSTATUS(status)))
			return _vz_error(ctx, VZS_ERR_SYSTEM, 
				"%s exited with code %d", task, rc);
	} else if (WIFSIGNALED(status)) {
		return _vz_error(ctx, VZS_ERR_SYSTEM, 
			"%s got signal %d", task, WTERMSIG(status));
	} else {
		return _vz_error(ctx, VZS_ERR_SYSTEM, 
			"%s exited with status %d", task, status);
	}
	return 0;
}

void _vzs_show_args(
		struct vzsock_ctx *ctx, 
		const char *title, 
		char * const *argv)
{
	char buffer[BUFSIZ];
	int i;

	if (!ctx->debug)
		return;

	strncpy(buffer, title, sizeof(buffer));
	for (i = 0; argv[i]; i++) {
		strncat(buffer, argv[i], sizeof(buffer)-strlen(buffer)-1);
		strncat(buffer, " ", sizeof(buffer)-strlen(buffer)-1);
	}
	_vz_logger(ctx, LOG_DEBUG, "%s", buffer);
}

