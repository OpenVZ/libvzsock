/* $Id: util.h,v 1.21 2008/06/26 14:40:12 krasnov Exp $
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 * Double-linked lists functions declarations
 */

#ifndef __VZM_UTIL_H__
#define __VZM_UTIL_H__

#include <sys/queue.h>

#include "libvzsock.h"

/* char* double-linked list */
TAILQ_HEAD(vz_string_list, vz_string_list_el);
struct vz_string_list_el {
	char *s;
	TAILQ_ENTRY(vz_string_list_el) e;
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
int _vz_logger(struct vzsock_ctx *ctx, int level, const char *fmt, ...);

/* put error code and error message in ctx and show error message */
int _vz_error(struct vzsock_ctx *ctx, int errcode, const char * fmt, ...);

/* get temporary directory */
int _vz_get_tmp_dir(char *path, size_t sz);

/* read password from stdin */
int _vz_read_password(const char *prompt, char *pass, size_t size);

/* char* double-linked list */
/* list initialization */
static inline void _vz_string_list_init(struct vz_string_list *ls)
{
	TAILQ_INIT(ls);
}

/* remove all elements and its content */
void _vz_string_list_clean(struct vz_string_list *ls);

/* add new element in tail */
int _vz_string_list_add(struct vz_string_list *ls, const char *str);

/* find string <str> in list <ls> */
struct vz_string_list_el * _vz_string_list_find(
		struct vz_string_list *ls, 
		const char *str);

/* remove element and its content and return pointer to previous elem */
struct vz_string_list_el * _vz_string_list_remove(
		struct vz_string_list *ls,
		struct vz_string_list_el *el);

/* 1 if list is empty */
static inline int _vz_string_list_empty(struct vz_string_list *ls)
{
	return (ls->tqh_first == NULL);
}

/* get size of string list <ls> */
size_t _vz_string_list_size(struct vz_string_list *ls);

/* copy string list <ls> to string array <*a> */
int _vz_string_list_to_array(struct vz_string_list *ls, char ***a);

/* copy string list <ls> to <buffer> */
int _vz_string_list_to_buf(
		struct vz_string_list *ls, 
		char *buffer, 
		size_t size);

#define _vz_string_list_for_each(ls, el) \
	for (	(el) = ((ls) != NULL) ? (ls)->tqh_first : NULL; \
		(el) != NULL; \
		(el) = (el)->e.tqe_next)



/* remove directory with content */
int _vz_rmdir(struct vzsock_ctx *ctx, const char *dirname);

#ifdef __cplusplus
}
#endif 

#endif
