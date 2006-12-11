/*
 *  NFSv4 ACL Code
 *  Pack an NFS4 ACL into an XDR encoded buffer.
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

#include <libacl_nfs4.h>
#include <netinet/in.h>

int acl_nfs4_xattr_pack(struct nfs4_acl * acl, char** bufp)
{
	struct nfs4_ace * ace;
	int buflen;
	int rbuflen;
	int num_aces;
	int ace_num;
	int wholen;
	int result;
	char* p;
	char* who;

	if(acl == NULL || bufp == NULL)
	{
		errno = EINVAL;
		goto failed;
	}

	buflen = acl_nfs4_xattr_size(acl);
	if(buflen < 0)
	{
		goto failed;
	}

	*bufp = (char*) malloc(buflen);
	if(*bufp == NULL) {
		errno = ENOMEM;
		goto failed;
	}

	p = *bufp;

	num_aces = acl->naces;

	*((u32*)p) = htonl(num_aces);

	rbuflen = sizeof(u32);
	p += sizeof(u32);

	ace = acl->ace_head.tqh_first;
	ace_num = 1;

	while(1)
	{
		if(ace == NULL)
		{
			if(ace_num > num_aces) {
				break;
			} else {
				errno = ENODATA;
				goto failed;
			}
		}

		*((u32*)p) = htonl(ace->type);
		p += sizeof(u32);
		rbuflen += sizeof(u32);

		*((u32*)p) = htonl(ace->flag);
		p += sizeof(u32);
		rbuflen += sizeof(u32);

		*((u32*)p) = htonl(ace->access_mask);
		p += sizeof(u32);
		rbuflen += sizeof(u32);

		result = acl_nfs4_get_who(ace, NULL, &who);
		if(result < 0) {
			goto free_failed;
		}

		wholen = strlen(who);
		*((u32*)p) = htonl(wholen);
		rbuflen += sizeof(u32);

		p += sizeof(u32);

		memcpy(p, who, wholen);
		free(who);

		p += (wholen / NFS4_XDR_MOD) * NFS4_XDR_MOD;
		if(wholen % NFS4_XDR_MOD) {
			p += NFS4_XDR_MOD;
		}

		rbuflen += (wholen / NFS4_XDR_MOD) * NFS4_XDR_MOD;
		if(wholen % NFS4_XDR_MOD) {
			rbuflen += NFS4_XDR_MOD;
		}

		ace = ace->l_ace.tqe_next;
		ace_num++;
	}

	if (buflen != rbuflen)
	{
		goto free_failed;
	}
	return buflen;

free_failed:
	free(*bufp);
	*bufp = NULL;

failed:
	return -1;
}



