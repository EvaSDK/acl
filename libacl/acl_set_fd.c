/*
  File: acl_set_fd.c

  Copyright (C) 1999, 2000
  Andreas Gruenbacher, <a.gruenbacher@bestbits.at>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <unistd.h>
#include <attr/xattr.h>
#include "libacl.h"
#include "__acl_to_xattr.h"

#ifdef USE_NFSV4_TRANS
 #include "libacl_nfs4.h"
 #include <nfsidmap.h>
#endif

#include "byteorder.h"
#include "acl_ea.h"


/* 23.4.21 */
int
acl_set_fd(int fd, acl_t acl)
{
	acl_obj *acl_obj_p = ext2int(acl, acl);
	char *ext_acl_p;
	const char *name = ACL_EA_ACCESS;
	size_t size;
	int error;
#ifdef USE_NFSV4_TRANS
	int retval;
	struct nfs4_acl * nacl;
#endif

	if (!acl_obj_p)
		return -1;

#ifdef USE_NFSV4_TRANS
	retval = fgetxattr(fd, ACL_NFS4_XATTR, NULL, 0);

	if(retval == -1 && (errno == ENOATTR || errno == EOPNOTSUPP)) {
		ext_acl_p = __acl_to_xattr(acl_obj_p, &size);
	} else {
		char domain[NFS4_MAX_DOMAIN_LEN];
		nfs4_init_name_mapping(NULL);
		error = nfs4_get_default_domain(NULL, domain, sizeof(domain));
		if (error)
			return -1;
		nacl = acl_nfs4_new(0);
		if (acl == NULL) {
			errno = ENOMEM;
			return -1;
		}
		error = acl_ptn4_acl_trans(acl, nacl, ACL_TYPE_ACCESS, 0, domain);
		if (error)
			return -1;

		size = acl_nfs4_xattr_pack(nacl, &ext_acl_p);
		name = ACL_NFS4_XATTR;
		acl_nfs4_free(nacl);
	}
#else
	ext_acl_p = __acl_to_xattr(acl_obj_p, &size);
#endif

	if (!ext_acl_p)
		return -1;
	error = fsetxattr(fd, name, (char *)ext_acl_p, size, 0);
	free(ext_acl_p);
	return error;
}

