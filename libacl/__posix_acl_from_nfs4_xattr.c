/*
 *  NFSv4 ACL Code
 *  Convert NFSv4 xattr values to a posix ACL
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

/* xattr_v is a char buffer filled with the nfsv4 xattr value.
 * xattr_size should be the byte count of the length of the xattr_v
 * data size. xattr_v may be larger than <xattr_size> bytes, but only
 * the first <xattr_size> bytes will be read. <type> is the posix acl
 * type requested. Currently either default, or access */

acl_t __posix_acl_from_nfs4_xattr(char* xattr_v,
		int xattr_size, acl_type_t ptype, u32 is_dir)
{
	struct nfs4_acl *	nfsacl = NULL;
	acl_t pacl;

	nfsacl = acl_nfs4_xattr_load(xattr_v, xattr_size, is_dir);
	if(nfsacl == NULL) {
		return NULL;
	}

	pacl = acl_n4tp_acl_trans(nfsacl, ptype);

	return pacl;
}

