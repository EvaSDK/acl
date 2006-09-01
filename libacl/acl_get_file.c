/*
  File: acl_get_file.c

  Copyright (C) 1999, 2000
  Andreas Gruenbacher, <a.gruenbacher@bestbits.at>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <attr/xattr.h>
#include <acl/libacl.h>
#include "libacl.h"
#include "__acl_from_xattr.h"

#ifdef USE_NFSV4_TRANS
 #include "libacl_nfs4.h"
#endif

#include "byteorder.h"
#include "acl_ea.h"


/* 23.4.16 */
acl_t
acl_get_file(const char *path_p, acl_type_t type)
{
	const size_t size_guess = acl_ea_size(16);
	char *ext_acl_p = alloca(size_guess);
	const char *name;
	int retval;
	int nfsv4acls;
	int iflags;

	switch(type) {
		case ACL_TYPE_ACCESS:
			name = ACL_EA_ACCESS;
			break;
		case ACL_TYPE_DEFAULT:
			name = ACL_EA_DEFAULT;
			break;
		default:
			errno = EINVAL;
			return NULL;
	}

	if (!ext_acl_p)
		return NULL;
#ifdef USE_NFSV4_TRANS
	retval = getxattr(path_p, ACL_NFS4_XATTR, ext_acl_p, size_guess);
	if((retval == -1) && (errno == ENOATTR || errno == EOPNOTSUPP)) {
		nfsv4acls = ACL_NFS4_NOT_USED;
		retval = getxattr(path_p, name, ext_acl_p, size_guess);
	} else {
		nfsv4acls = ACL_NFS4_USED;
		name = ACL_NFS4_XATTR;
	}
#else
	retval = getxattr(path_p, name, ext_acl_p, size_guess);
#endif

	if ((retval == -1) && (errno == ERANGE)) {
		retval = getxattr(path_p, name, NULL, 0);
		if (retval > 0) {
			ext_acl_p = alloca(retval);
			if (!ext_acl_p)
				return NULL;
			retval = getxattr(path_p, name, ext_acl_p, retval);
		}
	}
	if (retval > 0) {
#ifdef USE_NFSV4_TRANS
		if(nfsv4acls == ACL_NFS4_USED) {
			struct stat st;

			iflags = NFS4_ACL_ISFILE;

			if (stat(path_p, &st) != 0)
				return NULL;

			if (S_ISDIR(st.st_mode))
				iflags = NFS4_ACL_ISDIR;

			acl_t acl = __posix_acl_from_nfs4_xattr(ext_acl_p, retval, type,
					iflags);
			return acl;
		}
		else
#endif
		{
			acl_t acl = __acl_from_xattr(ext_acl_p, retval);
			return acl;
		}
	} else if ((retval == 0) || (errno == ENOATTR) || (errno == ENODATA)) {
		struct stat st;

		if (stat(path_p, &st) != 0)
			return NULL;

		if (type == ACL_TYPE_DEFAULT) {
			if (S_ISDIR(st.st_mode))
				return acl_init(0);
			else {
				errno = EACCES;
				return NULL;
			}
		} else
			return acl_from_mode(st.st_mode);
	} else
		return NULL;
}

