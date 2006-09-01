#
# Copyright (c) 2000-2002 Silicon Graphics, Inc.  All Rights Reserved.
#

TOPDIR = ..

LTLDFLAGS += -Wl,--version-script,$(TOPDIR)/exports
include $(TOPDIR)/include/builddefs

LTLIBRARY = libacl.la
LTLIBS = -lattr -lnfsidmap $(LIBMISC)
LTDEPENDENCIES = $(LIBMISC)
LT_CURRENT = 3
LT_REVISION = 0
LT_AGE = 2

CFILES = $(POSIX_CFILES) $(LIBACL_CFILES) $(LIBACL_NFS4_CFILES) \
	$(INTERNAL_CFILES) perm_copy_fd.c perm_copy_file.c

HFILES = libobj.h libacl.h byteorder.h __acl_from_xattr.h __acl_to_xattr.h \
	 perm_copy.h $(LIBACL_NFS4_HFILES)

LCFLAGS = -include perm_copy.h

LIBACL_NFS4_CFILES = \
	acl_n4tp_ace_count.c \
	acl_n4tp_ace_trans.c       acl_nfs4_get_who.c \
	acl_n4tp_acl_trans.c       acl_nfs4_get_whotype.c \
	acl_n4tp_get_whotype.c     acl_nfs4_new.c \
	acl_n4tp_set_mode.c        acl_n4tp_set_who.c \
	acl_nfs4_add_ace.c         acl_nfs4_remove_ace.c \
	acl_nfs4_add_pair.c \
	acl_nfs4_copy_acl.c        acl_nfs4_set_who.c \
	acl_nfs4_utils.c \
	acl_nfs4_free.c            acl_nfs4_xattr_load.c \
	acl_nfs4_xattr_pack.c      acl_nfs4_xattr_size.c \
	acl_ptn4_acl_trans.c \
	acl_ptn4_get_mask.c        __posix_acl_from_nfs4_xattr.c \


LIBACL_NFS4_HFILES = ../include/libacl_nfs4.h ../include/nfs4.h

POSIX_CFILES = \
	acl_add_perm.c acl_calc_mask.c acl_clear_perms.c acl_copy_entry.c \
	acl_copy_ext.c acl_copy_int.c acl_create_entry.c acl_delete_def_file.c \
	acl_delete_entry.c acl_delete_perm.c acl_dup.c acl_free.c \
	acl_from_text.c acl_get_entry.c acl_get_fd.c acl_get_file.c \
	acl_get_perm.c acl_get_permset.c acl_get_qualifier.c \
	acl_get_tag_type.c acl_init.c acl_set_fd.c acl_set_file.c \
	acl_set_permset.c acl_set_qualifier.c acl_set_tag_type.c acl_to_text.c \
	acl_valid.c acl_size.c

LIBACL_CFILES = \
	acl_to_any_text.c acl_entries.c acl_check.c acl_error.c acl_cmp.c \
	acl_extended_fd.c acl_extended_file.c acl_equiv_mode.c acl_from_mode.c

INTERNAL_CFILES = \
	__acl_to_any_text.c __acl_to_xattr.c __acl_from_xattr.c \
	__acl_reorder_obj_p.c __libobj.c __apply_mask_to_mode.c


default: $(LTLIBRARY)

include $(BUILDRULES)

install:

install-dev: default
	$(INSTALL_LTLIB_DEV)

install-lib: default
	$(INSTALL_LTLIB)
