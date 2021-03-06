/*
 * Copyright (c) 2001-2002 Silicon Graphics, Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __XATTR_H__
#define __XATTR_H__

#include <features.h>

#include <errno.h>
#ifndef ENOATTR
# define ENOATTR ENODATA        /* No such attribute */
#endif

#define XATTR_CREATE  0x1       /* set value, fail if attr already exists */
#define XATTR_REPLACE 0x2       /* set value, fail if attr does not exist */


__BEGIN_DECLS

extern int setxattr (const char *__path, const char *__name,
		      const void *__value, size_t __size, int __flags);
extern int lsetxattr (const char *__path, const char *__name,
		      const void *__value, size_t __size, int __flags);
extern int fsetxattr (int __filedes, const char *__name,
		      const void *__value, size_t __size, int __flags);

extern ssize_t getxattr (const char *__path, const char *__name,
				void *__value, size_t __size);
extern ssize_t lgetxattr (const char *__path, const char *__name,
				void *__value, size_t __size);
extern ssize_t fgetxattr (int __filedes, const char *__name,
				void *__value, size_t __size);

extern ssize_t listxattr (const char *__path, char *__list,
				size_t __size);
extern ssize_t llistxattr (const char *__path, char *__list,
				size_t __size);
extern ssize_t flistxattr (int __filedes, char *__list,
				size_t __size);

extern int removexattr (const char *__path, const char *__name);
extern int lremovexattr (const char *__path, const char *__name);
extern int fremovexattr (int __filedes,   const char *__name);

__END_DECLS

#endif	/* __XATTR_H__ */
