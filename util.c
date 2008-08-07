/* $Id: util.c,v 1.23 2008/06/30 13:21:14 krasnov Exp $
 *
 * Copyright (c) SWsoft, 2006-2007
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

static int _vz_def_logger(int level, const char* fmt, va_list pvar)
{
	/* put to syslog and to some output also */
	vsyslog(level, fmt, pvar);
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
		_vz_def_logger(level, fmt, pvar);
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
		_vz_def_logger(LOG_ERR, fmt, ap);
	va_end(pvar);
	va_end(ap);
	return errcode;
}

/* get temporary directory */
int _vz_get_tmp_dir(char *path, size_t sz)
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
int _vz_read_password(const char *prompt, char *pass, size_t size)
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
int _vz_string_list_add(struct vz_string_list *ls, const char *str)
{
	struct vz_string_list_el *p;

	p = (struct vz_string_list_el *)
		malloc(sizeof(struct vz_string_list_el));
	if (p == NULL)
		return VZS_ERR_SYSTEM;
	if ((p->s = strdup(str)) == NULL)
		return VZS_ERR_SYSTEM;
	TAILQ_INSERT_TAIL(ls, p, e);

	return 0;
}

/* remove all elements and its content */
void _vz_string_list_clean(struct vz_string_list *ls)
{
	struct vz_string_list_el *el;

	while (ls->tqh_first != NULL) {
		el = ls->tqh_first;
		TAILQ_REMOVE(ls, ls->tqh_first, e);
		free((void *)el->s);
		free((void *)el);
	}
}

/* find string <str> in list <ls> */
struct vz_string_list_el * _vz_string_list_find(
		struct vz_string_list *ls, 
		const char *str)
{
	struct vz_string_list_el *p;

	if (str == NULL)
		return NULL;

	for (p = ls->tqh_first; p != NULL; p = p->e.tqe_next) {
		if (strcmp(str, p->s) == 0)
			return p;
	}
	return NULL;
}

/* remove element and its content and return pointer to previous elem */
struct vz_string_list_el * _vz_string_list_remove(
		struct vz_string_list *ls,
		struct vz_string_list_el *el)
{
	/* get previous element */
	struct vz_string_list_el *prev = *el->e.tqe_prev;

	TAILQ_REMOVE(ls, el, e);
	free((void *)el->s);
	free((void *)el);

	return prev;
}

/* get size of string list <ls> */
size_t _vz_string_list_size(struct vz_string_list *ls)
{
	struct vz_string_list_el *p;
	size_t sz = 0;

	for (p = ls->tqh_first; p != NULL; p = p->e.tqe_next)
		sz++;
	return sz;
}

/* copy string list <ls> to string array <*a> */
int _vz_string_list_to_array(struct vz_string_list *ls, char ***a)
{
	struct vz_string_list_el *p;
	size_t sz, i;

	/* get array size */
	sz = _vz_string_list_size(ls);
	if ((*a = (char **)calloc(sz + 1, sizeof(char *))) == NULL)
		return VZS_ERR_SYSTEM;
	for (p = ls->tqh_first, i = 0; p != NULL && i < sz; \
				p = p->e.tqe_next, i++) {
		if (((*a)[i] = strdup(p->s)) == NULL)
			return VZS_ERR_SYSTEM;
	}
	(*a)[sz] = NULL;

	return 0;
}

/* copy string list <ls> to <buffer> */
int _vz_string_list_to_buf(
		struct vz_string_list *ls, 
		char *buffer, 
		size_t size)
{
	struct vz_string_list_el *p;

	_vz_string_list_for_each(ls, p) {
		strncat(buffer, p->s, size-strlen(buffer)-1);
		strncat(buffer, " ", size-strlen(buffer)-1);
	}
	return 0;
}

/* remove directory with content */
int _vz_rmdir(struct vzsock_ctx *ctx, const char *dirname)
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
			if ((rc = _vz_rmdir(ctx, path)))
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

