/*
 *  NFSv4 ACL Code
 *  Convert NFSv4 ACL to a POSIX ACL
 *
 *  Copyright (c) 2002, 2003 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Nathaniel Gallaher <ngallahe@umich.edu>
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
#include "libacl_nfs4.h"

acl_t acl_n4tp_acl_trans(struct nfs4_acl * nacl_p, acl_type_t ptype)
{

	acl_t pacl_p = NULL;
	acl_t * pacl_pp;
	struct nfs4_acl * temp_acl;
	int naces = -1;
	int num_aces;
	int ace_num;
	struct nfs4_ace * cur_ace = NULL;
	struct nfs4_ace * mask_ace = NULL;
	struct nfs4_ace * temp_ace = NULL;
	int result;
	u32 flags;
	u32 iflags = NFS4_ACL_NOFLAGS;

	if (nacl_p == NULL) {
		errno = EINVAL;
		goto failed;
	}

	if (ptype == ACL_TYPE_DEFAULT) {
		if (nacl_p->is_directory)
			iflags |= NFS4_ACL_REQUEST_DEFAULT;
		else {
			errno = EINVAL;
			goto failed;
		}
	}

	/* Copy so we can delete bits without borking the original */
	temp_acl = acl_nfs4_copy_acl(nacl_p);
	if (temp_acl == NULL)
		goto failed;

	num_aces = temp_acl->naces;

	/* Strip or keep inheritance aces depending upon the type of posix acl
	 * requested */
	cur_ace = acl_nfs4_get_first_ace(temp_acl);
	ace_num = 1;

	while(1) {
		if(cur_ace == NULL) {
			if(ace_num > num_aces)
				break;
			else
				goto free_failed;
		}

		/* get the next ace now because we may be freeing the current ace */
		temp_ace = cur_ace;
		acl_nfs4_get_next_ace(&cur_ace);

		flags = temp_ace->flag;

		if (iflags & NFS4_ACL_REQUEST_DEFAULT) {
			if((flags & NFS4_INHERITANCE_FLAGS) != NFS4_INHERITANCE_FLAGS)
				acl_nfs4_remove_ace(temp_acl, temp_ace);
		} else {
			if ((flags & NFS4_INHERITANCE_FLAGS) == NFS4_INHERITANCE_FLAGS) {
				acl_nfs4_remove_ace(temp_acl, temp_ace);
			}
		}

		ace_num++;
	}


	naces = acl_n4tp_ace_count(temp_acl);
	if (naces < 0) {
		errno = EINVAL;
		goto free_failed;
	}

	if (naces == 0)
		return acl_init(0);

	pacl_p = acl_init(naces);

	if(pacl_p == NULL)
		goto free_failed;

	pacl_pp = &pacl_p;

	cur_ace = acl_nfs4_get_first_ace(temp_acl);

	result = user_obj_from_v4(temp_acl, &cur_ace, pacl_pp, iflags);
	if(result < 0)
		goto acl_free_failed;

	result = users_from_v4(temp_acl, &cur_ace, &mask_ace, pacl_pp, iflags);
	if(result < 0)
		goto acl_free_failed;

	result = group_obj_and_groups_from_v4(temp_acl, &cur_ace,
			&mask_ace, pacl_pp, iflags);
	if(result < 0)
		goto acl_free_failed;

	result = mask_from_v4(temp_acl, &cur_ace, &mask_ace, pacl_pp, iflags);
	if(result < 0)
		goto acl_free_failed;

	result = other_from_v4(temp_acl, &cur_ace, pacl_pp, iflags);
	if(result < 0)
		goto acl_free_failed;

	result = acl_valid(*pacl_pp);
	if(result < 0)
		goto acl_free_failed;

	acl_nfs4_free(temp_acl);

	return *pacl_pp;

acl_free_failed:
	acl_free(*pacl_pp);

free_failed:
	acl_nfs4_free(temp_acl);

failed:
	return NULL;
}

