/*
 * Copyright (c) 2016-2017, Parallels International GmbH
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
 * Double-linked lists functions declarations
 */

#ifndef __VZM_UTIL_H__
#define __VZM_UTIL_H__

#include <sys/queue.h>

#include "libvzsock.h"

/* char* double-linked list */
TAILQ_HEAD(vzs_string_list, vzs_string_list_el);
struct vzs_string_list_el {
	char *s;
	TAILQ_ENTRY(vzs_string_list_el) e;
};

/* void * double-linked list */
TAILQ_HEAD(vzs_void_list, vzs_void_list_el);
struct vzs_void_list_el {
	void *p;
	TAILQ_ENTRY(vzs_void_list_el) e;
};

#ifdef __cplusplus
extern "C" {
#endif 

/* set block/nonblock mode for descriptor <fd>, 
   state==1 - block, otherwise - nonblock */
int __vz_set_block(int fd, int state);

/* set cloexec/noncloexec mode for descriptor <fd>, 
   state==1 - cloexec, otherwise - noncloexec */
int __vz_set_cloexec(int fd, int state);

#define _vz_set_block(fd) __vz_set_block(fd, 1)
#define _vz_set_nonblock(fd) __vz_set_block(fd, 0)
#define _vz_set_cloexec(fd) __vz_set_cloexec(fd, 1)
#define _vz_set_noncloexec(fd) __vz_set_cloexec(fd, 0)

/* show message */
int _vz_def_logger(int level, const char *fmt, ...);
int _vz_logger(struct vzsock_ctx *ctx, int level, const char *fmt, ...);

/* put error code and error message in ctx and show error message */
int _vz_error(struct vzsock_ctx *ctx, int errcode, const char * fmt, ...);

/* get temporary directory */
int _vzs_get_tmp_dir(char *path, size_t sz);

/* read password from stdin */
int _vzs_read_password(const char *prompt, char *pass, size_t size);

/* char* double-linked list */
/* list initialization */
static inline void _vzs_string_list_init(struct vzs_string_list *ls)
{
	TAILQ_INIT(ls);
}

/* remove all elements and its content */
void _vzs_string_list_clean(struct vzs_string_list *ls);

/* add new element in tail */
int _vzs_string_list_add(struct vzs_string_list *ls, const char *str);

/* find string <str> in list <ls> */
struct vzs_string_list_el * _vzs_string_list_find(
		struct vzs_string_list *ls, 
		const char *str);

/* remove element and its content and return pointer to previous elem */
struct vzs_string_list_el * _vzs_string_list_remove(
		struct vzs_string_list *ls,
		struct vzs_string_list_el *el);

/* 1 if list is empty */
static inline int _vzs_string_list_empty(struct vzs_string_list *ls)
{
	return (ls->tqh_first == NULL);
}

/* get size of string list <ls> */
size_t _vzs_string_list_size(struct vzs_string_list *ls);

/* copy string list <ls> to string array <*a> */
int _vzs_string_list_to_array(struct vzs_string_list *ls, char ***a);

/* copy string array into string list */
int _vzs_string_list_from_array(struct vzs_string_list *ls, char **a);

/* copy string list <ls> to <buffer> */
int _vzs_string_list_to_buf(
		struct vzs_string_list *ls, 
		char *buffer, 
		size_t size);

#define _vzs_string_list_for_each(ls, el) \
	for (	(el) = ((ls) != NULL) ? (ls)->tqh_first : NULL; \
		(el) != NULL; \
		(el) = (el)->e.tqe_next)

/* void * double-linked list */
/* list initialization */
static inline void _vzs_void_list_init(struct vzs_void_list *ls)
{
	TAILQ_INIT(ls);
}

/* remove all elements and its content */
void _vzs_void_list_clean(struct vzs_void_list *ls);

/* add new element in tail */
int _vzs_void_list_add(struct vzs_void_list *ls, const void *ptr);

/* remove element and its content and return pointer to previous elem */
struct vzs_void_list_el * _vzs_void_list_remove(
		struct vzs_void_list *ls,
		struct vzs_void_list_el *el);

#define _vzs_void_list_for_each(ls, el) \
	for (	(el) = ((ls) != NULL) ? (ls)->tqh_first : NULL; \
		(el) != NULL; \
		(el) = (el)->e.tqe_next)



/* remove directory with content */
int _vzs_rmdir(struct vzsock_ctx *ctx, const char *dirname);

/* Write <size> bytes of <data> in non-blocking descriptor <fd>. */
int _vzs_writefd(
		struct vzsock_ctx *ctx, 
		int fd, 
		const char * data, 
		size_t size,
		int silent);
/* 
  read from nonblocking descriptor <fd> string, separated by <separator>.
  will write '\0' on the end of string
*/
int _vzs_recv_str(
		struct vzsock_ctx *ctx, 
		int fd, 
		char separator, 
		char *data, 
		size_t *size);

int _vzs_check_exit_status(struct vzsock_ctx *ctx, char *task, int status);

void _vzs_show_args(
		struct vzsock_ctx *ctx, 
		const char *title, 
		char * const *argv);

#ifdef __cplusplus
}
#endif 

#endif
