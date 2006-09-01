/*
 *  NFSv4 ACL Code
 *  Set the POSIX ACE who based on the whotype and NFS who attr.
 *  Translation is done using the NFS4 mapping functions.
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
#include <nfsidmap.h>
#include "libacl_nfs4.h"

#define PATH_IDMAPDCONF "/etc/idmapd.conf"
char *conf_path = PATH_IDMAPDCONF;

int acl_n4tp_set_who(acl_entry_t ace, char* who, acl_tag_t who_type)
{
	int result;
	uid_t uid;
	gid_t gid;

	if(ace == NULL || who == NULL) {
		errno = EINVAL;
		goto failed;
	}

	switch(who_type) {
		case ACL_USER:
			result = nfs4_init_name_mapping(NULL);
			if (result < 0)
				goto failed;
			result = nfs4_name_to_uid(who, &uid);
			if(result < 0)
				goto failed;
			result = acl_set_qualifier(ace, (void *) &uid);
			if(result < 0)
				goto failed;
			break;
		case ACL_GROUP:
			result = nfs4_init_name_mapping(NULL);
			if (result < 0)
				goto failed;
			result = nfs4_name_to_gid(who, &gid);
			if(result < 0)
				goto failed;
			result = acl_set_qualifier(ace, (void *) &gid);
			if(result < 0)
				goto failed;
			break;
		default:
			errno = EINVAL;
			goto failed;
	}

	return 0;

failed:
	return -1;
}


