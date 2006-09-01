/*
 *  NFSv4 ACL Code
 *  Convert NFSv4 ACE who to a POSIX ACE whotype
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

acl_tag_t acl_n4tp_get_whotype(struct nfs4_ace *ace)
{
	int nfs4type;
	int result;

	if(ace == NULL)
		goto inval_failed;

	if(ace->who == NULL || strlen(ace->who) <= 0)
		goto inval_failed;

	result = acl_nfs4_get_who(ace, &nfs4type, NULL);
	if ( result < 0 )
		goto failed;

	switch (nfs4type) {
		case NFS4_ACL_WHO_NAMED:
			return (ace->flag & NFS4_ACE_IDENTIFIER_GROUP ?
					ACL_GROUP : ACL_USER);
		case NFS4_ACL_WHO_OWNER:
			return ACL_USER_OBJ;
		case NFS4_ACL_WHO_GROUP:
			return ACL_GROUP_OBJ;
		case NFS4_ACL_WHO_EVERYONE:
			return ACL_OTHER;
	}

inval_failed:
	errno = EINVAL;

failed:
	return -1;
}


