/*
 *  NFSv4 ACL Code
 *  Translate POSIX permissions to an NFSv4 mask
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
#include <libacl_nfs4.h>

int acl_ptn4_get_mask(u32* mask, acl_permset_t perms, int iflags)
{
	int result;

	*mask = NFS4_ANYONE_MODE;

	if (perms == NULL) {
		errno = EINVAL;
		goto failed;
	}

	if (iflags & NFS4_ACL_OWNER)
		*mask |= NFS4_OWNER_MODE;

	result = acl_get_perm(perms, ACL_READ);
	if (result < 0)
		goto failed;
	else if(result == 1)
		*mask |= NFS4_READ_MODE;

	result = acl_get_perm(perms, ACL_WRITE);
	if (result < 0)
		goto failed;
	else if (result == 1) {
		*mask |= NFS4_WRITE_MODE;
		if (iflags & NFS4_ACL_ISDIR)
			*mask |= NFS4_ACE_DELETE_CHILD;
	}

	result = acl_get_perm(perms, ACL_EXECUTE);
	if (result < 0)
		goto failed;
	else if (result == 1)
		*mask |= NFS4_EXECUTE_MODE;

	return 0;

failed:
	return -1;
}



