/*
  File: acl_set_file.c

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

#include <sys/types.h>
#include <sys/stat.h>
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

#ifdef USE_NFSV4_TRANS
static struct nfs4_acl *get_nfs4_acl(const char *path_p, int is_dir)
{
	struct nfs4_acl * acl = NULL;
	ssize_t ret;
	char *buf;

	ret = getxattr(path_p, ACL_NFS4_XATTR, NULL, 0);
	if (ret < 0)
		return NULL;
	buf = malloc(ret);
	if (buf == NULL)
		return NULL;
	ret = getxattr(path_p, ACL_NFS4_XATTR, buf, ret);
	if (ret < 0)
		goto out_free;
	acl = acl_nfs4_xattr_load(buf, ret, is_dir);

out_free:
	free(buf);
	return acl;
}

#endif

/* 23.4.22 */
int
acl_set_file(const char *path_p, acl_type_t type, acl_t acl)
{
	acl_obj *acl_obj_p = ext2int(acl, acl);
	char *ext_acl_p;
	const char *name;
	size_t size;
	int error;
	struct stat st;
#ifdef USE_NFSV4_TRANS
	struct nfs4_acl * nacl;
	int is_dir = NFS4_ACL_ISFILE;
#endif

	if (!acl_obj_p)
		return -1;

	switch (type) {
		case ACL_TYPE_ACCESS:
			name = ACL_EA_ACCESS;
			break;
		case ACL_TYPE_DEFAULT:
			name = ACL_EA_DEFAULT;
			break;
		default:
			errno = EINVAL;
			return -1;
	}


#ifdef USE_NFSV4_TRANS
	if (stat(path_p, &st) != 0)
		return -1;
	if (S_ISDIR(st.st_mode))
		is_dir = NFS4_ACL_ISDIR;
	if (type == ACL_TYPE_DEFAULT && !is_dir) {
		errno = EACCES;
		return -1;
	}
	nacl = get_nfs4_acl(path_p, is_dir);
	if (nacl == NULL && (errno == ENOATTR || errno == EOPNOTSUPP))
		ext_acl_p = __acl_to_xattr(acl_obj_p, &size);
	else {
		char domain[NFS4_MAX_DOMAIN_LEN];

		nfs4_init_name_mapping(NULL);
		error = nfs4_get_default_domain(NULL, domain, sizeof(domain));
		if (error) {
			acl_nfs4_free(nacl);
			return -1;
		}
		error = acl_ptn4_acl_trans(acl, nacl, type, is_dir, domain);
		if (error) {
			acl_nfs4_free(nacl);
			return -1;
		}

		size = acl_nfs4_xattr_pack(nacl, &ext_acl_p);
		name = ACL_NFS4_XATTR;
		acl_nfs4_free(nacl);
	}
#else

	if (type == ACL_TYPE_DEFAULT) {

		if (stat(path_p, &st) != 0)
			return -1;

		/* Only directories may have default ACLs. */
		if (!S_ISDIR(st.st_mode)) {
			errno = EACCES;
			return -1;
		}
	}

	ext_acl_p = __acl_to_xattr(acl_obj_p, &size);
#endif

	if (!ext_acl_p)
		return -1;
	error = setxattr(path_p, name, (char *)ext_acl_p, size, 0);
	free(ext_acl_p);
	return error;
}

