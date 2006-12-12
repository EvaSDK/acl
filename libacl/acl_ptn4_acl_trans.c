/*
 *  NFSv4 ACL Code
 *  Convert a posix ACL to an NFSv4 ACL
 *
 *  Copyright (c) 2002, 2003 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Nathaniel Gallaher <ngallahe@umich.edu>
 *  J. Bruce Fields <bfields@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <acl/libacl.h>
#include <nfsidmap.h>
#include "libacl_nfs4.h"


#define FILE_OR_DIR_INHERIT (NFS4_ACE_FILE_INHERIT_ACE \
		| NFS4_ACE_DIRECTORY_INHERIT_ACE)
#define NFS4_INHERITANCE_FLAGS (FILE_OR_DIR_INHERIT | NFS4_ACE_INHERIT_ONLY_ACE)

/* Plan:
 * 1: if setting default, remove all purely inherited aces, and replace
 *    all dual-use aces by purely effective aces
 * 2: if setting effective, remove all purely effective aces, and replace
 *    all dual-use aces by purely inherited ones
 */
static void purge_aces(struct nfs4_acl *nacl, acl_type_t type)
{
	struct nfs4_ace *p, *next;

	for (p = nacl->ace_head.tqh_first; p != NULL; p = next) {
		next = p->l_ace.tqe_next;

		if (!(p->flag & FILE_OR_DIR_INHERIT)) {
			/* purely effective */
			if (type == ACL_TYPE_ACCESS)
				acl_nfs4_remove_ace(nacl, p);
		} else if (p->flag & NFS4_ACE_INHERIT_ONLY_ACE) {
			/* purely inherited */
			if (type == ACL_TYPE_DEFAULT)
				acl_nfs4_remove_ace(nacl, p);
		} else {
			/* both effective and inherited */
			if (type == ACL_TYPE_DEFAULT) {
				/* Change to purely effective */
				p->flag &= ~NFS4_INHERITANCE_FLAGS;
			} else { /* ACL_TYPE_ACCESS */
				/* Change to purely inherited */
				p->flag |= NFS4_INHERITANCE_FLAGS;
			}
		}

	}
}
 
int
acl_ptn4_acl_trans(acl_t pacl, struct nfs4_acl *acl, acl_type_t type, u32 is_dir, char *nfs_domain)
{
	int eflag;
	u32 mask, mask_mask = 0;
	int num_aces;
	int result, result2;
	u32 iflags = NFS4_ACL_NOFLAGS;
	int allocated = 0;

	acl_entry_t pace_p;
	acl_tag_t ace_type;
	acl_permset_t perms;

	char who_buf_static[NFS4_ACL_WHO_BUFFER_LEN_GUESS];
	char *who_buf = NULL;
	int who_buflen;
	int who_buflen_static = NFS4_ACL_WHO_BUFFER_LEN_GUESS;
	uid_t * uid_p;
	gid_t * gid_p;

	eflag = 0;

	if (type == ACL_TYPE_DEFAULT) {
		eflag = NFS4_INHERITANCE_FLAGS;
		iflags |= NFS4_ACL_REQUEST_DEFAULT;
	}

	purge_aces(acl, type);

	if (is_dir & NFS4_ACL_ISDIR)
		iflags |= NFS4_ACL_ISDIR;


	if (pacl == NULL || (acl_valid(pacl) < 0 || acl_entries(pacl) == 0)) {
		errno = EINVAL;
		goto out;
	}

	/* Start Conversion */

	/* 3 aces minimum (mode bits) */
	num_aces = acl_entries(pacl);
	if (num_aces < 3) {
		errno = EINVAL;
		goto out;
	}

	/* Get the mask entry */

	result = acl_get_entry(pacl, ACL_FIRST_ENTRY, &pace_p);
	if (result < 0)
		goto out;

	while (result > 0 && mask_mask == 0) {
		result = acl_get_tag_type(pace_p, &ace_type);
		if (result < 0)
			goto out;

		if (ace_type == ACL_MASK) {
			result = acl_get_permset(pace_p, &perms);
			if(result < 0)
				goto out;

			result = acl_ptn4_get_mask(&mask_mask, perms, iflags);
			if(result < 0)
				goto out;

			mask_mask = ~mask_mask;
		}

		result = acl_get_entry(pacl, ACL_NEXT_ENTRY, &pace_p);
		if (result < 0)
			goto out;
	}

	/* Get the file owner entry */
	result = acl_get_entry(pacl, ACL_FIRST_ENTRY, &pace_p);
	if (result < 0)
		goto out;

	result = acl_get_tag_type(pace_p, &ace_type);
	if (result < 0)
		goto out;

	if (ace_type != ACL_USER_OBJ) {
		errno = EINVAL;
		goto out;
	}

	result = acl_get_permset(pace_p, &perms);
	if (result < 0)
		goto out;

	result = acl_ptn4_get_mask(&mask, perms, iflags | NFS4_ACL_OWNER);
	if (result < 0)
		goto out;

	result = acl_nfs4_add_pair(acl, eflag, mask, NFS4_ACL_WHO_OWNER, NULL);

	if (result < 0)
		goto out;

	result = acl_get_entry(pacl, ACL_NEXT_ENTRY, &pace_p);
	if (result < 0)
		goto out;

	result2 = acl_get_tag_type(pace_p, &ace_type);
	if (result2 < 0)
		goto out;

	while (ace_type == ACL_USER && result > 0) {
		result = acl_get_permset(pace_p, &perms);
		if (result < 0)
			goto out;

		result = acl_ptn4_get_mask(&mask, perms, iflags);
		if (result < 0)
			goto out;

		uid_p = acl_get_qualifier(pace_p);

		who_buf = who_buf_static;
		who_buflen = who_buflen_static;

		result = nfs4_init_name_mapping(NULL);
		result = nfs4_uid_to_name(*uid_p, nfs_domain, who_buf, who_buflen);


		while (result == -ENOBUFS) {
			if (who_buf != who_buf_static)
				free(who_buf);

			/* Increase the size by a full buflen unit */
			who_buflen += who_buflen_static;
			who_buf = malloc(who_buflen);

			if (who_buf == NULL) {
				result = -ENOMEM;
				break;
			}

			result = nfs4_init_name_mapping(NULL);
			result = nfs4_uid_to_name(*uid_p, nfs_domain, who_buf, who_buflen);

		}
		acl_free(uid_p);
		if (result < 0) {
			errno = -result;
			goto out;
		}

		if (who_buf == NULL)
			goto out;

		result = acl_nfs4_add_ace(acl, NFS4_ACE_ACCESS_DENIED_ACE_TYPE,
				eflag,  mask_mask, NFS4_ACL_WHO_NAMED, who_buf);
		if (result < 0) {
			if(who_buf != who_buf_static)
				free(who_buf);
			goto out;
		}

		result = acl_nfs4_add_pair(acl, eflag, mask, NFS4_ACL_WHO_NAMED,
				who_buf);
		if (who_buf != who_buf_static)
			free(who_buf);
		if (result < 0)
			goto out;

		result = acl_get_entry(pacl, ACL_NEXT_ENTRY, &pace_p);
		if (result <= 0)
			goto out;

		result2 = acl_get_tag_type(pace_p, &ace_type);
		if (result2 < 0)
			goto out;

	}

	/* In the case of groups, we apply allow ACEs first, then deny ACEs,
	 * since a user can be in more than one group.  */

	/* allow ACEs */

	if (num_aces > 3) {
		result2 = acl_get_tag_type(pace_p, &ace_type);
		if (result2 < 0)
			goto out;

		if (ace_type != ACL_GROUP_OBJ) {
			errno = EINVAL;
			goto out;
		}

		result = acl_nfs4_add_ace(acl, NFS4_ACE_ACCESS_DENIED_ACE_TYPE,
				NFS4_ACE_IDENTIFIER_GROUP | eflag, mask_mask,
				NFS4_ACL_WHO_GROUP, NULL);

		if (result < 0)
			goto out;
	}

	result = acl_get_permset(pace_p, &perms);
	if (result < 0)
		goto out;

	result = acl_ptn4_get_mask(&mask, perms, iflags);
	if (result < 0)
		goto out;

	result = acl_nfs4_add_ace(acl, NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
			NFS4_ACE_IDENTIFIER_GROUP | eflag, mask, NFS4_ACL_WHO_GROUP, NULL);

	if (result < 0)
		goto out;

	result = acl_get_entry(pacl, ACL_NEXT_ENTRY, &pace_p);
	if (result <= 0)
		goto out;

	result2 = acl_get_tag_type(pace_p, &ace_type);
	if (result2 < 0)
		goto out;

	while (ace_type == ACL_GROUP && result > 0) {
		result = acl_get_permset(pace_p, &perms);
		if (result < 0)
			goto out;

		result = acl_ptn4_get_mask(&mask, perms, iflags);
		if (result < 0)
			goto out;

		gid_p = acl_get_qualifier(pace_p);

		who_buf = who_buf_static;
		who_buflen = who_buflen_static;

		result = nfs4_gid_to_name(*gid_p, nfs_domain, who_buf, who_buflen);


		while (result == -ENOBUFS) {
			if (who_buf != who_buf_static)
				free(who_buf);

			/* Increase the size by a full buflen unit */
			who_buflen += who_buflen_static;
			who_buf = malloc(who_buflen);

			if (who_buf == NULL) {
				result = -ENOMEM;
				break;
			}

			result = nfs4_gid_to_name(*gid_p, nfs_domain, who_buf, who_buflen);
		}

		acl_free(gid_p);

		if (result < 0) {
			errno = -result;
			goto out;
		}

		if (who_buf == NULL)
			goto out;

		result = acl_nfs4_add_ace(acl, NFS4_ACE_ACCESS_DENIED_ACE_TYPE,
				NFS4_ACE_IDENTIFIER_GROUP | eflag, mask_mask,
				NFS4_ACL_WHO_NAMED, who_buf);
		if (result < 0) {
			if(who_buf != who_buf_static)
				free(who_buf);
			goto out;
		}

		result = acl_nfs4_add_ace(acl, NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
		    	NFS4_ACE_IDENTIFIER_GROUP | eflag, mask,
				NFS4_ACL_WHO_NAMED, who_buf);

		if (who_buf != who_buf_static)
			free(who_buf);

		if (result < 0)
			goto out;
		result = acl_get_entry(pacl, ACL_NEXT_ENTRY, &pace_p);
		if (result <= 0)
			goto out;

		result2 = acl_get_tag_type(pace_p, &ace_type);
		if (result2 < 0)
			goto out;
	}

	/* deny ACEs */

	result = acl_get_entry(pacl, ACL_FIRST_ENTRY, &pace_p);
	if (result <= 0)
		goto out;

	result2 = acl_get_tag_type(pace_p, &ace_type);
	if (result2 < 0)
		goto out;

	while (ace_type != ACL_GROUP_OBJ && result > 0) {
		result = acl_get_entry(pacl, ACL_NEXT_ENTRY, &pace_p);
		if(result <= 0)
			goto out;

		result2 = acl_get_tag_type(pace_p, &ace_type);
		if(result2 < 0)
			goto out;
	}

	result = acl_get_permset(pace_p, &perms);
	if (result < 0)
		goto out;

	result = acl_ptn4_get_mask(&mask, perms, iflags);
	if (result < 0)
		goto out;

	result = acl_nfs4_add_ace(acl, NFS4_ACE_ACCESS_DENIED_ACE_TYPE,
			NFS4_ACE_IDENTIFIER_GROUP | eflag, ~mask, NFS4_ACL_WHO_GROUP,
			NULL);

	if (result < 0)
		goto out;

	result = acl_get_entry(pacl, ACL_NEXT_ENTRY, &pace_p);
	if (result <= 0)
		goto out;

	result2 = acl_get_tag_type(pace_p, &ace_type);
	if (result2 < 0)
		goto out;

	while (ace_type == ACL_GROUP && result > 0) {
		result = acl_get_permset(pace_p, &perms);
		if (result < 0)
			goto out;

		result = acl_ptn4_get_mask(&mask, perms, iflags);
		if (result < 0)
			goto out;

		gid_p = acl_get_qualifier(pace_p);

		who_buf = who_buf_static;
		who_buflen = who_buflen_static;

		result = nfs4_gid_to_name(*gid_p, nfs_domain, who_buf, who_buflen);


		while (result == -ENOBUFS) {
			if (who_buf != who_buf_static)
				free(who_buf);

			/* Increase the size by a full buflen unit */
			who_buflen += who_buflen_static;
			who_buf = malloc(who_buflen);

			if (who_buf == NULL) {
				result = -ENOMEM;
				break;
			}

			result = nfs4_gid_to_name(*gid_p, nfs_domain, who_buf, who_buflen);
		}

		acl_free(gid_p);

		if (result < 0) {
			errno = -result;
			goto out;
		}

		if (who_buf == NULL)
			goto out;

		result = acl_nfs4_add_ace(acl, NFS4_ACE_ACCESS_DENIED_ACE_TYPE,
		    		NFS4_ACE_IDENTIFIER_GROUP | eflag, ~mask,
					NFS4_ACL_WHO_NAMED, who_buf);
		if (who_buf != who_buf_static)
			free(who_buf);
		if (result < 0)
			goto out;

		result = acl_get_entry(pacl, ACL_NEXT_ENTRY, &pace_p);
		if (result <= 0)
			goto out;

		result2 = acl_get_tag_type(pace_p, &ace_type);
		if (result2 < 0)
			goto out;
	}

	if (ace_type == ACL_MASK) {
		result = acl_get_entry(pacl, ACL_NEXT_ENTRY, &pace_p);
		if (result <= 0)
			goto out;

		result2 = acl_get_tag_type(pace_p, &ace_type);
		if (result2 < 0)
			goto out;
	}

	if (ace_type != ACL_OTHER) {
		errno = EINVAL;
		goto out;
	}

	result = acl_get_permset(pace_p, &perms);
	if (result < 0)
		goto out;

	result = acl_ptn4_get_mask(&mask, perms, iflags);
	if (result < 0)
		goto out;

	result = acl_nfs4_add_pair(acl, eflag, mask, NFS4_ACL_WHO_EVERYONE, NULL);

	return result;
out:
	if (allocated)
		acl_nfs4_free(acl);
	return -1;
}
