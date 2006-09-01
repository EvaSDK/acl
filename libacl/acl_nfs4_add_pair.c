/*
 *  Add a pair of aces to the acl. The ace masks are complements of each other
 *  This keeps us from walking off the end of the acl
 *
 *  Copyright (c) 2004 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Marius Aamodt Eriksen <marius@umich.edu>
 *  J. Bruce Fields <bfields@umich.edu>
 *  Nathaniel Gallaher <ngallahe@umich.edu>
 *  Jeff Sedlak <jsedlak@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions, the following disclaimer, and
 *     any and all other licensing or copyright notices included in
 *     any files in this distribution.
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
 *
 */


#include "libacl_nfs4.h"

int
acl_nfs4_add_pair(struct nfs4_acl *acl, int eflag, u32 mask, int ownertype,
		char* owner)
{
	int error;

	error = acl_nfs4_add_ace(acl, NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
				 eflag, mask, ownertype, owner);
	if (error < 0)
		return error;
	error = acl_nfs4_add_ace(acl, NFS4_ACE_ACCESS_DENIED_ACE_TYPE,
				eflag, ~mask, ownertype, owner);
	return error;
}


