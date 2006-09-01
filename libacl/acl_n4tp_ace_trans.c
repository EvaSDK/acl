/*
 *  NFSv4 ACL Code
 *  Translate an NFSv4 ace to a POSIX ace.
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

int acl_n4tp_ace_trans(struct nfs4_ace *ace, acl_t *pacl, acl_tag_t tag,
		int iflags)
{
	int result;
	acl_entry_t new_ace;


	if(ace == NULL || pacl == NULL || *pacl == NULL) {
		errno = EINVAL;
		goto failed;
	}

	result = acl_create_entry(pacl, &new_ace);
	if(result < 0)
		goto failed;

	result = acl_set_tag_type(new_ace, tag);
	if(result < 0)
		goto ace_failed;

	result = acl_n4tp_set_mode(new_ace, ace->access_mask, iflags);
	if(result < 0)
		goto ace_failed;

	if(tag == ACL_USER || tag == ACL_GROUP) {
		result = acl_n4tp_set_who(new_ace, ace->who, tag);
		if(result < 0)
			goto ace_failed;
	}

	return 0;

ace_failed:
	acl_delete_entry(*pacl, new_ace);

failed:
	return -1;
}

