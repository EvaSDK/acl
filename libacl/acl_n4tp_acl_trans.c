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
#include <nfsidmap.h>
#include "libacl_nfs4.h"


/*
 * While processing the NFSv4 ACE, this maintains bitmasks representing
 * which permission bits have been allowed and which denied to a given
 * entity: */
struct posix_ace_state {
	u_int32_t allow;
	u_int32_t deny;
};

struct posix_user_ace_state {
	uid_t uid;
	struct posix_ace_state perms;
};

struct posix_ace_state_array {
	int n;
	struct posix_user_ace_state aces[];
};

/*
 * While processing the NFSv4 ACE, this maintains the partial permissions
 * calculated so far: */

struct posix_acl_state {
	struct posix_ace_state owner;
	struct posix_ace_state group;
	struct posix_ace_state other;
	struct posix_ace_state everyone;
	struct posix_ace_state mask; /* Deny unused in this case */
	struct posix_ace_state_array *users;
	struct posix_ace_state_array *groups;
};

static int
init_state(struct posix_acl_state *state, int cnt)
{
	int alloc;

	memset(state, 0, sizeof(struct posix_acl_state));
	/*
	 * In the worst case, each individual acl could be for a distinct
	 * named user or group, but we don't know which, so we allocate
	 * enough space for either:
	 */
	alloc = sizeof(struct posix_ace_state_array)
		+ cnt*sizeof(struct posix_user_ace_state);
	state->users = calloc(1, alloc);
	if (!state->users)
		return -ENOMEM;
	state->groups = calloc(1, alloc);
	if (!state->groups) {
		free(state->users);
		return -ENOMEM;
	}
	return 0;
}

static void
free_state(struct posix_acl_state *state) {
	free(state->users);
	free(state->groups);
}

static inline void add_to_mask(struct posix_acl_state *state, struct posix_ace_state *astate)
{
	state->mask.allow |= astate->allow;
}

/*
 * We only map from NFSv4 to POSIX ACLs when getting ACLs, when we err on the
 * side of permissiveness (so as not to make the file appear more secure than
 * it really is), so the mode bit mapping below is optimistic.
 */
static void
set_mode_from_nfs4(acl_entry_t pace, u_int32_t perm, int is_dir)
{
	u32 write_mode = NFS4_WRITE_MODE;
	acl_permset_t perms;

	acl_get_permset(pace, &perms);
	acl_clear_perms(perms);
	if (is_dir)
		write_mode |= NFS4_ACE_DELETE_CHILD;
	if (perm & NFS4_READ_MODE)
		acl_add_perm(perms, ACL_READ);
	if (perm & write_mode)
		acl_add_perm(perms, ACL_WRITE);
	if (perm & NFS4_EXECUTE_MODE)
		acl_add_perm(perms, ACL_EXECUTE);
	acl_set_permset(pace, perms);
}

/* XXX: add a "check allow" that can warn on e.g. allows of WRITE_ACL
 * to non-owner? */

/* XXX: replace error returns by errno sets all over.  Ugh. */

static acl_t
posix_state_to_acl(struct posix_acl_state *state, int is_dir)
{
	acl_entry_t pace;
	acl_t pacl;
	int nace;
	int i, error = 0;

	if (state->users->n || state->groups->n)
		nace = 4 + state->users->n + state->groups->n;
	else
		nace = 3;
	pacl = acl_init(nace);
	if (!pacl)
		return NULL;

	error = acl_create_entry(&pacl, &pace);
	if (error)
		goto out_err;
	acl_set_tag_type(pace, ACL_USER_OBJ);
	set_mode_from_nfs4(pace, state->owner.allow, is_dir);

	for (i=0; i < state->users->n; i++) {
		error = acl_create_entry(&pacl, &pace);
		if (error)
			goto out_err;
		acl_set_tag_type(pace, ACL_USER);
		set_mode_from_nfs4(pace, state->users->aces[i].perms.allow,
					is_dir);
		acl_set_qualifier(pace, &state->users->aces[i].uid);
		add_to_mask(state, &state->users->aces[i].perms);
	}

	error = acl_create_entry(&pacl, &pace);
	if (error)
		goto out_err;
	acl_set_tag_type(pace, ACL_GROUP_OBJ);
	set_mode_from_nfs4(pace, state->group.allow, is_dir);
	add_to_mask(state, &state->group);

	for (i=0; i < state->groups->n; i++) {
		error = acl_create_entry(&pacl, &pace);
		if (error)
			goto out_err;
		acl_set_tag_type(pace, ACL_GROUP);
		set_mode_from_nfs4(pace, state->groups->aces[i].perms.allow,
					is_dir);
		acl_set_qualifier(pace, &state->groups->aces[i].uid);
		add_to_mask(state, &state->groups->aces[i].perms);
	}

	if (nace > 3) {
		error = acl_create_entry(&pacl, &pace);
		if (error)
			goto out_err;
		acl_set_tag_type(pace, ACL_MASK);
		set_mode_from_nfs4(pace, state->mask.allow, is_dir);
	}

	error = acl_create_entry(&pacl, &pace);
	if (error)
		goto out_err;
	acl_set_tag_type(pace, ACL_OTHER);
	set_mode_from_nfs4(pace, state->other.allow, is_dir);

	return pacl;
out_err:
	acl_free(pacl);
	return NULL;
}

static inline void allow_bits(struct posix_ace_state *astate, u32 mask)
{
	/* Allow all bits in the mask not already denied: */
	astate->allow |= mask & ~astate->deny;
}

static inline void deny_bits(struct posix_ace_state *astate, u32 mask)
{
	/* Deny all bits in the mask not already allowed: */
	astate->deny |= mask & ~astate->allow;
}

static int find_uid(struct posix_acl_state *state, uid_t uid)
{
	int i;
	struct posix_ace_state_array *users = state->users;

	for (i = 0; i < users->n; i++)
		if (users->aces[i].uid == uid)
			return i;
	/* Not found: */
	users->n++;
	users->aces[i].uid = uid;
	users->aces[i].perms.allow = state->everyone.allow;
	users->aces[i].perms.deny  = state->everyone.deny;

	return i;
}

static int find_gid(struct posix_acl_state *state, uid_t uid)
{
	int i;
	struct posix_ace_state_array *groups = state->groups;

	for (i = 0; i < groups->n; i++)
		if (groups->aces[i].uid == uid)
			return i;
	/* Not found: */
	groups->n++;
	groups->aces[i].uid = uid;
	groups->aces[i].perms.allow = state->other.allow;
	groups->aces[i].perms.deny  = state->other.deny;

	return i;
}

static void deny_bits_array(struct posix_ace_state_array *a, u32 mask)
{
	int i;

	for (i=0; i < a->n; i++)
		deny_bits(&a->aces[i].perms, mask);
}

static void allow_bits_array(struct posix_ace_state_array *a, u32 mask)
{
	int i;

	for (i=0; i < a->n; i++)
		allow_bits(&a->aces[i].perms, mask);
}

static acl_tag_t acl_n4tp_get_whotype(struct nfs4_ace *ace)
{
	int nfs4type;
	int result;

	result = acl_nfs4_get_who(ace, &nfs4type, NULL);
	if (result < 0)
		return -1;

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
	errno = EINVAL;
	return -1;
}

static int process_one_v4_ace(struct posix_acl_state *state,
				struct nfs4_ace *ace)
{
	u32 mask = ace->access_mask;
	uid_t id;
	int i;

	if (nfs4_init_name_mapping(NULL))
		return -1;

	switch (acl_n4tp_get_whotype(ace)) {
	case ACL_USER_OBJ:
		if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
			allow_bits(&state->owner, mask);
		} else {
			deny_bits(&state->owner, mask);
		}
		break;
	case ACL_USER:
		if (nfs4_name_to_uid(ace->who, &id))
			return -1;
		i = find_uid(state, id);
		if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
			allow_bits(&state->users->aces[i].perms, mask);
			mask = state->users->aces[i].perms.allow;
			allow_bits(&state->owner, mask);
		} else {
			deny_bits(&state->users->aces[i].perms, mask);
		}
		break;
	case ACL_GROUP_OBJ:
		if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
			allow_bits(&state->group, mask);
			mask = state->group.allow;
			allow_bits(&state->owner, mask);
			allow_bits(&state->everyone, mask);
			allow_bits_array(state->users, mask);
		} else {
			deny_bits(&state->group, mask);
		}
		break;
	case ACL_GROUP:
		if (nfs4_name_to_gid(ace->who, &id))
			return -1;
		i = find_gid(state, id);
		if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
			allow_bits(&state->groups->aces[i].perms, mask);
			mask = state->groups->aces[i].perms.allow;
			allow_bits(&state->owner, mask);
			allow_bits(&state->everyone, mask);
			allow_bits_array(state->users, mask);
		} else {
			deny_bits(&state->groups->aces[i].perms, mask);
		}
		break;
	case ACL_OTHER:
		if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
			allow_bits(&state->owner, mask);
			allow_bits(&state->group, mask);
			allow_bits(&state->other, mask);
			allow_bits(&state->everyone, mask);
			allow_bits_array(state->users, mask);
			allow_bits_array(state->groups, mask);
		} else {
			deny_bits(&state->owner, mask);
			deny_bits(&state->group, mask);
			deny_bits(&state->other, mask);
			deny_bits(&state->everyone, mask);
			deny_bits_array(state->users, mask);
			deny_bits_array(state->groups, mask);
		}
	}
	return 0;
}

#define FILE_OR_DIR_INHERIT (NFS4_ACE_FILE_INHERIT_ACE \
				| NFS4_ACE_DIRECTORY_INHERIT_ACE)

/* Strip or keep inheritance aces depending on type of posix acl requested */
static void acl_nfs4_check_inheritance(struct nfs4_acl *acl, u32 iflags)
{
	struct nfs4_ace * cur_ace;
	struct nfs4_ace * temp_ace;

	cur_ace = acl->ace_head.tqh_first;

	while (cur_ace) {
		/* get the next ace now in case we free the current ace */
		temp_ace = cur_ace;
		cur_ace = cur_ace->l_ace.tqe_next;

		if (iflags & NFS4_ACL_REQUEST_DEFAULT) {
			if (!(temp_ace->flag & FILE_OR_DIR_INHERIT))
				acl_nfs4_remove_ace(acl, temp_ace);
		} else {
			if (temp_ace->flag & NFS4_ACE_INHERIT_ONLY_ACE)
				acl_nfs4_remove_ace(acl, temp_ace);
		}
	}
}

acl_t acl_n4tp_acl_trans(struct nfs4_acl * nacl_p, acl_type_t ptype)
{
	struct posix_acl_state state;
	acl_t pacl;
	struct nfs4_acl * temp_acl;
	struct nfs4_ace * cur_ace;
	int ret;
	u32 iflags = NFS4_ACL_NOFLAGS;

	if (ptype == ACL_TYPE_DEFAULT) {
		if (nacl_p->is_directory)
			iflags |= NFS4_ACL_REQUEST_DEFAULT;
		else {
			errno = EINVAL;
			return NULL;
		}
	}

	/* Copy so we can delete bits without borking the original */
	temp_acl = acl_nfs4_copy_acl(nacl_p);
	if (temp_acl == NULL)
		return NULL;

	acl_nfs4_check_inheritance(temp_acl, iflags);

	if (ptype == ACL_TYPE_DEFAULT && temp_acl->naces == 0) {
		acl_nfs4_free(temp_acl);
		return acl_init(0);
	}

	ret = init_state(&state, temp_acl->naces);
	if (ret)
		goto free_failed;

	cur_ace = temp_acl->ace_head.tqh_first;
	while (cur_ace) {
		if (process_one_v4_ace(&state, cur_ace)) {
			free_state(&state);
			goto free_failed;
		}
		cur_ace = cur_ace->l_ace.tqe_next;
	}

	acl_nfs4_free(temp_acl);

	pacl = posix_state_to_acl(&state, nacl_p->is_directory);

	free_state(&state);

	ret = acl_valid(pacl);
	if (ret < 0)
		goto free_failed;

	return pacl;

free_failed:
	acl_nfs4_free(temp_acl);
	return NULL;
}
