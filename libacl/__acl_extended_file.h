typedef ssize_t (*getxattr_t)(const char *, const char *, void *value,
        size_t size);

int __acl_extended_file(const char *path_p, getxattr_t fun);
