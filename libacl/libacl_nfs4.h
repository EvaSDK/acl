#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/acl.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <nfs4.h>
#include <sys/errno.h>
#include <string.h>

/* mode bit translations: */
#define NFS4_READ_MODE NFS4_ACE_READ_DATA
#define NFS4_WRITE_MODE (NFS4_ACE_WRITE_DATA \
		| NFS4_ACE_APPEND_DATA | NFS4_ACE_DELETE_CHILD)
#define NFS4_EXECUTE_MODE NFS4_ACE_EXECUTE
#define NFS4_ANYONE_MODE (NFS4_ACE_READ_ATTRIBUTES | NFS4_ACE_READ_ACL | \
		NFS4_ACE_SYNCHRONIZE)
#define NFS4_OWNER_MODE (NFS4_ACE_WRITE_ATTRIBUTES | NFS4_ACE_WRITE_ACL)

/* flags used to simulate posix default ACLs */
#define NFS4_INHERITANCE_FLAGS (NFS4_ACE_FILE_INHERIT_ACE \
		| NFS4_ACE_DIRECTORY_INHERIT_ACE | NFS4_ACE_INHERIT_ONLY_ACE)

#define NFS4_ACE_MASK_IGNORE (NFS4_ACE_DELETE | NFS4_ACE_WRITE_OWNER \
		| NFS4_ACE_READ_NAMED_ATTRS | NFS4_ACE_WRITE_NAMED_ATTRS)
/* XXX not sure about the following.  Note that e.g. DELETE_CHILD is wrong in
 * general (should only be ignored on files). */
#define MASK_EQUAL(mask1, mask2) \
	(((mask1) & NFS4_ACE_MASK_ALL & ~NFS4_ACE_MASK_IGNORE & \
	  					~NFS4_ACE_DELETE_CHILD) \
	 == ((mask2) & NFS4_ACE_MASK_ALL & ~NFS4_ACE_MASK_IGNORE & \
		 				~NFS4_ACE_DELETE_CHILD))

/* Maximum length of the ace->who attribute */
#define NFS4_ACL_WHO_LENGTH_MAX		2048
#define NFS4_ACL_WHO_BUFFER_LEN_GUESS	255

/* NFS4 acl xattr name */
#define ACL_NFS4_XATTR "system.nfs4_acl"

/* Macro for finding empty tailqs */
#define TAILQ_IS_EMPTY(head) (head.tqh_first == NULL)

/* Flags to pass certain properties around */
#define NFS4_ACL_NOFLAGS			0x00
#define NFS4_ACL_ISFILE				0x00
#define NFS4_ACL_ISDIR				0x01
#define NFS4_ACL_OWNER				0x02
#define NFS4_ACL_REQUEST_DEFAULT	0x04
#define NFS4_ACL_RAW				0x01

#define NFS4_XDR_MOD				4

typedef u_int32_t u32;

enum {	ACL_NFS4_NOT_USED = 0,
		ACL_NFS4_USED
};

struct ace_container {
	struct nfs4_ace *ace;
	TAILQ_ENTRY(ace_container) l_ace;
};

TAILQ_HEAD(ace_container_list_head, ace_container);

/**** Public functions ****/

/** Manipulation functions **/
extern int				acl_nfs4_add_ace(struct nfs4_acl *, u32, u32, u32, int, char*);
extern int				acl_nfs4_add_pair(struct nfs4_acl *, int, u32, int, char*);
extern void				acl_nfs4_free(struct nfs4_acl *);
extern struct nfs4_acl *acl_nfs4_new(u32);
extern int				acl_nfs4_set_who(struct nfs4_ace*, int, char*);
extern struct nfs4_acl *acl_nfs4_copy_acl(struct nfs4_acl *);
extern struct nfs4_acl *acl_nfs4_xattr_load(char *, int, u32);
extern int				acl_nfs4_xattr_pack(struct nfs4_acl *, char**);
extern int				acl_nfs4_xattr_size(struct nfs4_acl *);
extern void				acl_nfs4_remove_ace(struct nfs4_acl * acl, struct nfs4_ace * ace);

/** Conversion functions **/

/* nfs4 -> posix */
extern acl_t		acl_n4tp_acl_trans(struct nfs4_acl *, acl_type_t);
extern int			acl_n4tp_set_mode(acl_entry_t pace, u32 nfs4_access_mask,
							int iflags);
extern int			acl_n4tp_ace_count(struct nfs4_acl *n4acl);
extern int			acl_n4tp_ace_trans(struct nfs4_ace *ace, acl_t *pacl,
							acl_tag_t tag, int iflags);
extern int			acl_n4tp_set_who(acl_entry_t ace, char* who,
							acl_tag_t who_type);
extern acl_tag_t	acl_n4tp_get_whotype(struct nfs4_ace *ace);

/* posix -> nfs4 */
extern int				acl_ptn4_get_mask(u32* mask, acl_permset_t perms,
								int iflags);
extern int acl_ptn4_acl_trans(acl_t, struct nfs4_acl *, acl_type_t, u32, char*);


/** Access Functions **/
extern inline struct nfs4_ace *
					acl_nfs4_get_next_ace(struct nfs4_ace **);
extern inline struct nfs4_ace *
					acl_nfs4_get_first_ace(struct nfs4_acl *);
extern inline int	acl_nfs4_get_whotype(char*);
extern int			acl_nfs4_get_who(struct nfs4_ace*, int*, char**);

/**** Private(?) functions ****/
acl_t		__posix_acl_from_nfs4_xattr(char*, int, acl_type_t, u32);
int complementary_ace_pair(struct nfs4_ace *allow, struct nfs4_ace *deny);
int same_who(struct nfs4_ace *a, struct nfs4_ace *b);

/* These will change */
int nfs4_get_gid_from_who(gid_t* gid, const char * who);
int nfs4_get_uid_from_who(uid_t* uid, const char * who);
char * nfs4_get_who_from_uid(uid_t);
char * nfs4_get_who_from_gid(gid_t);
int __nfs4_get_local_uid_from_who(uid_t* uid, const char * who);
int __nfs4_get_foreign_uid_from_who(uid_t* uid, const char * who);
int __nfs4_get_local_gid_from_who(gid_t* gid, const char * who);
int __nfs4_get_foreign_gid_from_who(gid_t* gid, const char * who);
int is_who_local(const char * who);
/* End change */

int user_obj_from_v4(struct nfs4_acl *n4acl, struct nfs4_ace **n4ace,
		acl_t *pacl, int iflags);
int users_from_v4(struct nfs4_acl *n4acl, struct nfs4_ace ** n4ace_p,
		struct nfs4_ace **mask_ace, acl_t *pacl, int iflags);
int group_obj_and_groups_from_v4(struct nfs4_acl *n4acl,
		struct nfs4_ace ** n4ace_p, struct nfs4_ace **mask_ace, acl_t *pacl, int iflags);
int mask_from_v4(struct nfs4_acl *n4acl, struct nfs4_ace ** n4ace_p,
		struct nfs4_ace **mask_ace, acl_t *pacl, int iflags);
int other_from_v4(struct nfs4_acl *n4acl, struct nfs4_ace ** n4ace_p,
		acl_t *pacl, int iflags);
