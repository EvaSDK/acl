/*
 *  NFSv4 ACL Code
 *  Deep copy an NFS4 ACL
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

#include "libacl_nfs4.h"

struct nfs4_acl * acl_nfs4_copy_acl(struct nfs4_acl * nacl)
{
	struct nfs4_acl * new_acl;
	struct nfs4_ace * ace;
	u32 nace;
	u32 num_aces;
	int result;

	if(nacl == NULL) {
		errno = EINVAL;
		goto failed;
	}

	num_aces = nacl->naces;

	new_acl = acl_nfs4_new(nacl->is_directory);
	if(new_acl == NULL)
		goto failed;

	ace = nacl->ace_head.tqh_first;
	nace = 1;

	while(1)
	{
		if(ace == NULL) {
			if(nace > num_aces)
				break;
			else
				goto free_failed;
		}

		result = acl_nfs4_add_ace(new_acl, ace->type, ace->flag,
				ace->access_mask, acl_nfs4_get_whotype(ace->who), ace->who);
		if(result < 0)
			goto free_failed;

		ace = ace->l_ace.tqe_next;
		nace++;
	}

	return new_acl;

free_failed:
	acl_nfs4_free(new_acl);

failed:
	return NULL;
}
