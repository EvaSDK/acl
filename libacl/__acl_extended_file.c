/*
  File: __acl_extended_file.c

  Copyright (C) 2000, 2011
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
#include "libacl_nfs4.h"

#include "byteorder.h"
#include "acl_ea.h"
#include "__acl_extended_file.h"


int
__acl_extended_file(const char *path_p,
		    ssize_t (*fun)(const char *, const char *,
				   void *, size_t))
{
	int base_size = sizeof(acl_ea_header) + 3 * sizeof(acl_ea_entry);
	int retval;

	/* XXX: Ugh: what's the easiest way to do this, taking
	 * into account default acl's, and that length alone won't do this?
	 * Also I'm a little uncomfortable with the amount of #ifdef
	 * NFS4 stuff that's going on.  We need a cleaner separation. */
#ifdef USE_NFSV4_TRANS
	retval = fun(path_p, ACL_NFS4_XATTR, NULL, 0);
	if (retval < 0 && errno != ENOATTR && errno != EOPNOTSUPP)
		return -1;
	if (retval >= 0) {
		struct nfs4_acl *nfsacl;
		char *ext_acl_p = alloca(retval);
		if (!ext_acl_p)
			return -1;

		retval = fun(path_p, ACL_NFS4_XATTR, ext_acl_p, retval);
		if (retval == -1)
			return -1;

		nfsacl = acl_nfs4_xattr_load(ext_acl_p, retval, NFS4_ACL_ISFILE);
		if (nfsacl) {
			int count = nfsacl->naces;
			acl_nfs4_free(nfsacl);
			return count > 6;
		}
		return 0;
	}
#endif

	retval = fun(path_p, ACL_EA_ACCESS, NULL, 0);
	if (retval < 0 && errno != ENOATTR && errno != ENODATA)
		return -1;
	if (retval > base_size)
		return 1;
	retval = fun(path_p, ACL_EA_DEFAULT, NULL, 0);
	if (retval < 0 && errno != ENOATTR && errno != ENODATA)
		return -1;
	if (retval >= base_size)
		return 1;
	return 0;
}
