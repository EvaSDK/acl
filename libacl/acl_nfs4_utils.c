#include <acl/libacl.h>
#include "libacl_nfs4.h"

int user_obj_from_v4(struct nfs4_acl *n4acl, struct nfs4_ace **n4ace,
		 acl_t *pacl, int iflags)
{
	struct nfs4_ace *ace = *n4ace;
	struct nfs4_ace *ace2;

	if (ace == NULL)
		goto inval_out;

	if (pacl == NULL || *pacl == NULL)
		goto inval_out;

	if (acl_n4tp_get_whotype(ace) != ACL_USER_OBJ)
		goto inval_out;

	if(acl_n4tp_ace_trans(ace, pacl, ACL_USER_OBJ, iflags|NFS4_ACL_OWNER) < 0)
		goto out;

	ace2 = acl_nfs4_get_next_ace(n4ace);
	if (ace2 == NULL)
		goto inval_out;

	if (!complementary_ace_pair(ace, ace2))
		goto inval_out;

	ace2 = acl_nfs4_get_next_ace(n4ace);

	return 0;

inval_out:
	errno = EINVAL;
out:
	return -1;
}

/* public */
inline struct nfs4_ace * acl_nfs4_get_next_ace(struct nfs4_ace ** ace)
{
	if(ace == NULL || (*ace) == NULL)
		return NULL;

	(*ace) = (*ace)->l_ace.tqe_next;
	return *ace;
}

/* public */
inline struct nfs4_ace * acl_nfs4_get_first_ace(struct nfs4_acl * acl)
{
	if(acl == NULL)
		return NULL;

	return acl->ace_head.tqh_first;
}




int nfs4_get_gid_from_who(gid_t* gid, const char * who)
{
	int islocal;
	int result;

	if(who == NULL || gid == NULL) {
		errno = EINVAL;
		goto failed;
	}

	islocal = is_who_local(who);
	if(islocal < 0)
		goto failed;
	else if (islocal == 1)
		result = __nfs4_get_local_gid_from_who(gid, who);
	else
		result = __nfs4_get_foreign_gid_from_who(gid, who);

	if(result < 0)
		goto failed;

	return 0;

failed:
	return -1;
}

int __nfs4_get_local_gid_from_who(gid_t* gid, const char * who)
{
	/* XXX Just trim things at the @. We need to pull the local domain
	 * name from the conf file for comparison, and handle foriegn names
	 * as well. Tie this in with idmapd and gssvcd */
	/* Special whos? */

	struct group * grent;
	char * gname_buf = NULL;
	int gname_buflen;
	char * char_pos = NULL;
	int char_posi;


	if(who == NULL) {
		errno = EINVAL;
		goto failed;
	}

	gname_buflen = strlen(who);
	if(gname_buflen <= 0) {
		errno = EINVAL;
		goto failed;
	}

	char_pos = strchr(who, '@');
	char_posi = char_pos - who;

	if((gname_buf = (char*) malloc(sizeof(char) * (char_posi + 1))) == NULL)
	{
		errno = ENOMEM;
		goto failed;
	}

	strncpy(gname_buf, who, char_posi);
	gname_buf[char_posi] = '\0';

	grent = getgrnam(gname_buf);
	free(gname_buf);

	if(grent == NULL)
		goto failed;

	*gid = grent->gr_gid;

	return 0;

failed:
	return -1;
}

int __nfs4_get_foreign_gid_from_who(gid_t* gid, const char * who)
{
	return -1;
}


int nfs4_get_uid_from_who(uid_t* uid, const char * who)
{
	int islocal;
	int result;

	if(who == NULL || uid == NULL) {
		errno = EINVAL;
		goto failed;
	}

	islocal = is_who_local(who);
	if(islocal < 0)
		goto failed;
	else if (islocal == 1)
		result = __nfs4_get_local_uid_from_who(uid, who);
	else
		result = __nfs4_get_foreign_uid_from_who(uid, who);

	if(result < 0)
		goto failed;

	return 0;

failed:
	return -1;
}

int __nfs4_get_local_uid_from_who(uid_t* uid, const char * who)
{
	/* XXX Just trim things at the @. We need to pull the local domain
	 * name from the conf file for comparison, and handle foriegn names
	 * as well. Tie this in with idmapd and gssvcd */
	/* Special whos? */

	char* lname_buf;
	char* char_pos;
	int lname_buflen;
	struct passwd *pwent;
	int char_posi;

	if(who == NULL) {
		errno = EINVAL;
		goto failed;
	}

	lname_buflen = strlen(who);
	if(lname_buflen <= 0) {
		errno = EINVAL;
		goto failed;
	}

	char_pos = strchr(who, '@');
	char_posi = char_pos - who;

	if((lname_buf = (char*) malloc(sizeof(char) * (char_posi + 1))) == NULL)
	{
		errno = ENOMEM;
		goto failed;
	}

	strncpy(lname_buf, who, char_posi);
	lname_buf[char_posi] = '\0';

	pwent = getpwnam(lname_buf);
	free(lname_buf);

	if(pwent == NULL)
		goto failed;

	*uid = pwent->pw_uid;

	return 0;

failed:
	return -1;
}



int is_who_local(const char * who)
{
	/* -1 on error, 0 for no, 1 for yes */
	/* TODO: Compare domain to local domain */
	if(who == NULL){
		errno = EINVAL;
		return -1;
	}

	if(strchr(who, '@') == NULL) {
		errno = EINVAL;
		return -1;
	}

	return 1;
}

int __nfs4_get_foreign_uid_from_who(uid_t* uid, const char * who)
{
	/* TODO: Make this work */
	return -1;
}



int users_from_v4(struct nfs4_acl *n4acl, struct nfs4_ace ** n4ace_p,
		struct nfs4_ace **mask_ace, acl_t *pacl, int iflags)
{
	struct nfs4_ace *ace, *ace2;
	int result;

	ace = *n4ace_p;

	if (ace == NULL) {
		goto inval_failed;
	}

	while (ace != NULL && acl_n4tp_get_whotype(ace) == ACL_USER) {
		if (ace->type != NFS4_ACE_ACCESS_DENIED_ACE_TYPE)
			goto inval_failed;
		if (*mask_ace &&
			!MASK_EQUAL(ace->access_mask, (*mask_ace)->access_mask))
			goto inval_failed;
		*mask_ace = ace;

		ace = acl_nfs4_get_next_ace(n4ace_p);
		if (ace == NULL)
			goto inval_failed;
		if (ace->type != NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE)
			goto inval_failed;
		result = acl_n4tp_ace_trans(ace, pacl, ACL_USER, iflags);
		if (result < 0)
			goto failed;

		ace2 = acl_nfs4_get_next_ace(n4ace_p);
		if (ace2 == NULL)
			goto failed;
		if (!complementary_ace_pair(ace, ace2))
			goto failed;
		if ((*mask_ace)->flag != ace2->flag ||
				!same_who(*mask_ace, ace2))
			goto failed;
		ace = acl_nfs4_get_next_ace(n4ace_p);
	}

	return 0;

inval_failed:
	errno = EINVAL;

failed:
	return -1;
}

int complementary_ace_pair(struct nfs4_ace *allow, struct nfs4_ace *deny)
{
	return MASK_EQUAL(allow->access_mask, ~deny->access_mask) &&
		allow->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE &&
		deny->type == NFS4_ACE_ACCESS_DENIED_ACE_TYPE &&
		allow->flag == deny->flag &&
		same_who(allow, deny);
}

int same_who(struct nfs4_ace *a, struct nfs4_ace *b)
{
	if(!strcmp(a->who, b->who) && strlen(a->who) == strlen(b->who))
		return 1;
	return 0;
}

int group_obj_and_groups_from_v4(struct nfs4_acl *n4acl,
		struct nfs4_ace ** n4ace_p, struct nfs4_ace **mask_ace,
		acl_t *pacl, int iflags)
{
	struct nfs4_ace *ace, *ace2;
	int num_aces;
	struct ace_container_list_head ace_list;
	struct ace_container *ace_c = NULL;
	int result;

	TAILQ_INIT(&ace_list);

	ace = *n4ace_p;

	num_aces = acl_n4tp_ace_count(n4acl);

	if(num_aces < 0)
		goto inval_failed;

	/* group owner (mask and allow aces) */

	if (num_aces != 3) {
		/* then the group owner should be preceded by mask */
		if (ace->type != NFS4_ACE_ACCESS_DENIED_ACE_TYPE)
			goto inval_failed;

		/* If we already got a mask, and it doesn't match this one... */
		if (*mask_ace &&
			!MASK_EQUAL(ace->access_mask, (*mask_ace)->access_mask))
			goto inval_failed;
		*mask_ace = ace;
		ace = acl_nfs4_get_next_ace(n4ace_p);
		if (ace == NULL)
			goto inval_failed;

		if ((*mask_ace)->flag != ace->flag || !same_who(*mask_ace, ace))
			goto inval_failed;
	}

	if (acl_n4tp_get_whotype(ace) != ACL_GROUP_OBJ)
		goto inval_failed;

	if((ace_c = malloc(sizeof(struct ace_container))) == NULL) {
		errno = ENOMEM;
		goto failed;
	}
	ace_c->ace = ace;

	TAILQ_INSERT_TAIL(&ace_list, ace_c, l_ace);

	if (ace->type != NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE)
		goto inval_failed;

	result = acl_n4tp_ace_trans(ace, pacl, ACL_GROUP_OBJ, iflags);
	if (result < 0)
		goto inval_failed;

	ace = acl_nfs4_get_next_ace(n4ace_p);
	if (ace == NULL)
		goto inval_failed;

	/* groups (mask and allow aces) */

	while (acl_n4tp_get_whotype(ace) == ACL_GROUP) {
		if (*mask_ace == NULL)
			goto inval_failed;

		if (ace->type != NFS4_ACE_ACCESS_DENIED_ACE_TYPE ||
			!MASK_EQUAL(ace->access_mask, (*mask_ace)->access_mask))
			goto inval_failed;
		*mask_ace = ace;

		ace = acl_nfs4_get_next_ace(n4ace_p);
		if (ace == NULL)
			goto inval_failed;

		if (ace->type != NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE ||
				!same_who(ace, *mask_ace))
			goto inval_failed;

		if((ace_c = malloc(sizeof(struct ace_container))) == NULL) {
			errno = ENOMEM;
			goto failed;
		}
		ace_c->ace = ace;

		TAILQ_INSERT_TAIL(&ace_list, ace_c, l_ace);

		result = acl_n4tp_ace_trans(ace, pacl, ACL_GROUP, iflags);
		if (result < 0)
			goto inval_failed;

		ace = acl_nfs4_get_next_ace(n4ace_p);
		if (ace == NULL)
			goto inval_failed;
	}

	/* group owner (deny ace) */

	if (acl_n4tp_get_whotype(ace) != ACL_GROUP_OBJ)
		goto inval_failed;

	ace_c = ace_list.tqh_first;
	ace2 = ace_c->ace;
	if (!complementary_ace_pair(ace2, ace))
		goto inval_failed;
	TAILQ_REMOVE(&ace_list, ace_c, l_ace);
	free(ace_c);

	/* groups (deny aces) */

	while (!TAILQ_IS_EMPTY(ace_list)) {
		ace = acl_nfs4_get_next_ace(n4ace_p);
		if (ace == NULL)
			goto inval_failed;
		if (acl_n4tp_get_whotype(ace) != ACL_GROUP)
			goto inval_failed;
		ace_c = ace_list.tqh_first;
		ace2 = ace_c->ace;
		if (!complementary_ace_pair(ace2, ace))
			goto inval_failed;
		TAILQ_REMOVE(&ace_list, ace_c, l_ace);
		free(ace_c);
	}

	ace = acl_nfs4_get_next_ace(n4ace_p);
	if (ace == NULL)
		goto inval_failed;
	if (acl_n4tp_get_whotype(ace) != ACL_OTHER)
		goto inval_failed;

	return 0;

inval_failed:
	errno = EINVAL;

failed:
	while (!TAILQ_IS_EMPTY(ace_list)) {
		ace_c = ace_list.tqh_first;
		TAILQ_REMOVE(&ace_list, ace_c, l_ace);
		free(ace_c);
	}
	return -1;
}

int
other_from_v4(struct nfs4_acl *n4acl,
		struct nfs4_ace ** n4ace_p, acl_t *pacl, int iflags)
{
	int result;
	struct nfs4_ace *ace, *ace2;

	ace = *n4ace_p;
	if (ace->type != NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE)
		goto inval_failed;

	result = acl_n4tp_ace_trans(ace, pacl, ACL_OTHER, iflags);
	if (result < 0)
		goto failed;

	ace2 = acl_nfs4_get_next_ace(n4ace_p);
	if (ace2 == NULL)
		goto inval_failed;

	if (!complementary_ace_pair(ace, ace2))
		goto inval_failed;

	return 0;

inval_failed:
	errno = EINVAL;

failed:
	return -1;
}

int mask_from_v4(struct nfs4_acl *n4acl,
		struct nfs4_ace ** n4ace_p, struct nfs4_ace **mask_ace,
		acl_t *pacl, int iflags)
{
	int result;
	struct nfs4_ace *ace;

	ace = *n4ace_p;
	if (acl_n4tp_ace_count(n4acl) != 3) {
		if (*mask_ace == NULL)
			goto inval_failed;
		(*mask_ace)->access_mask = ~(*mask_ace)->access_mask;

		result = acl_n4tp_ace_trans(*mask_ace, pacl, ACL_MASK, iflags);
		if(result < 0)
			goto failed;

		//ace = acl_nfs4_get_next_ace(n4ace_p);
		//if (ace == NULL)
		//	goto inval_failed;
	}

	return 0;

inval_failed:
	errno = EINVAL;

failed:
	return -1;
}


/*
static inline int
match_who(struct nfs4_ace *ace, uid_t owner, gid_t group, uid_t who)
{
	switch (ace->whotype) {
		case NFS4_ACL_WHO_NAMED:
			return who == ace->who;
		case NFS4_ACL_WHO_OWNER:
			return who == owner;
		case NFS4_ACL_WHO_GROUP:
			return who == group;
		case NFS4_ACL_WHO_EVERYONE:
			return 1;
		default:
			return 0;
	}
}
*/
/* 0 = granted, -EACCES = denied; mask is an nfsv4 mask, not mode bits */
/*
int
nfs4_acl_permission(struct nfs4_acl *acl, uid_t owner, gid_t group,
			uid_t who, u32 mask)
{
	struct nfs4_ace *ace;
	u32 allowed = 0;

	list_for_each_entry(ace, &acl->ace_head, l_ace) {
		if (!match_who(ace, group, owner, who))
			continue;
		switch (ace->type) {
			case NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE:
				allowed |= ace->access_mask;
				if ((allowed & mask) == mask)
					return 0;
				break;
			case NFS4_ACE_ACCESS_DENIED_ACE_TYPE:
				if (ace->access_mask & mask)
					return -EACCES;
				break;
		}
	}
	return -EACCES;
}
*/
