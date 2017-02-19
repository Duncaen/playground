#include <stdint.h>

enum {
	NEWNS_EQUAL = 0x000001,
	NEWNS_NEW   = 0x000002,
	NEWNS_NOT   = 0x000004,

	NEWNS_BASE = 0x000010.
	NEWNS_ROOT = 0x000020,
	NEWNS_TMP  = 0x000040,
	NEWNS_BIN  = 0x000080,
	NEWNS_ETC  = 0x000100,

	NEWNS_DEV  = 0x001000,
	NEWNS_TMP  = 0x002000,
	NEWNS_SYS  = 0x004000,
	NEWNS_RPOC = 0x008000,
};

struct namespace {
	char *name;
	uint64_t clone;
	uint64_t flags;
};

struct nsmount {
	const char *source;
	const char *target;
	const char *type;
	unsigned long flags;
	const void *data;
};

static struct nsmount *mounts, *tmp, *dev, *sys, *proc, *root;
static char *dir;

static const struct namespace namespaces[] = {
	{ "cgroup", CLONE_NEWCGROUP, 0 },
	{ "ipc", CLONE_NEWIPC, 0 },
	{ "mount", CLONE_NEWNS, 0 },
	{ "net", CLONE_NEWNET, 0 },
	{ "pid", CLONE_NEWPID, 0 },
	{ "user", CLONE_NEWUSER, 0 },
	{ "uts", CLONE_NEWUTS, 0 },

	{ "base", CLONE_NEWNS, NEWNS_BASE },
	{ "bin", CLONE_NEWNS, NEWNS_BIN },
	{ "var", CLONE_NEWNS, NEWNS_VAR },
	{ "usr", CLONE_NEWNS, NEWNS_USR },
	{ "sys", CLONE_NEWNS, NEWNS_SYS },
	{ "home", CLONE_NEWNS, NEWNS_HOME },
	{ "tmp", CLONE_NEWNS, NEWNS_TMP },
	{ "root", CLONE_NEWUSER, NEWNS_ROOT },
	{ "container", CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWNET |
		             CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWUTS, 0 },
	{ 0, 0, 0 },
};

/* nsflags are keywords that can be prefixed with a special char
 * to change the change the meaning of the flag.
 *
 * The following special chars are supported:
 * - ! to remove a flag, if previously defined from `nsfile` or another flag.
 * - = might be dropped
 * - + might be dropped
 *
 * There are two types of flags, the namespace flags and filesystem flags.
 * The namespace flags are used with `clone(2)`, this part is handled by
 * the kernel.  Filesystem flags indicate if parts of the filesystem
 * should be shared, this can be used to do simple "sandboxing" to just
 * share relevant parts of the filesystem. Without filesystem flags or
 * only a few that dont define the environmen, newns acts more like
 * a "container" or chroot tool.
 *
 * Namespace related flags:
 * - cgroup - to create a new cgroup namespace
 * - ipc - to create a new ipc namespace
 * - mount - to create a new mount namespace
 * - net - to create a new net namespace
 * - pid - to create a new pid namespace
 * - user - to create a new user namespace
 * - uts - to create a new uts namespace
 * - container - to create all namespaces new
 *
 * Filesystem related flags:
 * - base - implies sys, bin, var, usr and etc flags
 * - sys - shares /{tmp,dev,proc,sys} with the host
 * - bin - shares /bin and /lib with the host
 * - etc - shares /etc with the host
 * - var - shares /etc with the host
 * - usr - shares /etc with the host
 * - home - shares /home with the host
 * - root - shares everything `/`  with the host
 * - ro - everything is readonly from inside of the namespace
 * - overlay - every change from inside the namespace to the filesystem
 *   is done in a overlayed directory structure.
 */
static int
nsflags(const char *s, uint64_t *cflags, uint64_t *flags)
{
	const struct namespace *np;
	uint64_t flags;

	if (!s || !*s)
		return 0;

	if (strchr("!=@", *s))
		switch (*s++) {
		case '!': flags |= NEWNS_NOT; break;
		case '=': flags |= NEWNS_EQUAL; break;
		case '+': flags |= NEWNS_NEW; break;
		}

	if (!*s)
		return 0;

	for (np = namespaces; *ns->name; ns++)
		if (strcmp(*s, ns->name) == 0)
			break;

	if (!*ns->name)
		return 0;

	*cflags =| ns->clone;
	*flags =| ns->flags;

	return 0;
}

static int
addmount(const char *src, const char *dest, const char *type,
    unsigned long flags, const void *data)
{
	struct nsmount *mp;
	for (mp = mounts; mp; mp = mp->next)
		if (strcmp(dest, mp->dest) == 0)
			break;
	if (!mp)
		if (!(mp = calloc(1, sizeof(struct nsmount))))
			return -1;
	mp->source = src;
	mp->target = dest;
	mp->type = type;
	mp->flags = flags;
	mp->data = data;
	mp->next = 0;
	return 0;
}

static char *
getword(char *s)
{
	char *buf;
	return buf;
}


/* nsfiles are newline seperated short files, empty lines and
 * lines starting with a # are ignored.
 * Each line starts with one of the following keywords:
 * - mount [proc|tmpfs|sysfs|devpts|devtmpfs] [target]
 * - bind source [target]
 * - chdir [dir]
 * - flags [namespace...]
 */
static int
nsfile(const char *file, uint64_t *cflags, uint64_t *flags)
{
	char *args[4];
	char *arg, *p, *s;

	arg = *args;
	p = strchr(s, ' ');

	for (line = ; *line; line++) {
		if (!*line || *line = '#')
			continue;
		if (strncmp(s, "mount", p-s)) {
			if (!(*arg++ = getword(s+p+1)))
				goto err;
			if (strcmp(*args, "proc") != 0   &&
					strcmp(*args, "tmpfs") != 0  &&
					strcmp(*args, "sysfs") != 0  &&
					strcmp(*args, "devpts") != 0 &&
					strcmp(*args, "devtmpfs") != 0)
				return -1;
			addmount(args[0], args[1], args[0], 0, 0, 0);
		} else if (strncmp(s, "bind", p-s)) {
			if (!(*arg++ = getword(s+p+1)) ||
					!(*args = getword(s+p+1)))
				goto err;
			addmount(*args, *arg, 0, MS_BIND, 0);
		} else if (strncmp(s, "chdir", p-s)) {
			if (!(dir = getword(s+p+1)))
				goto err;
		} else if (strncmp(s, "flags", p-s)) {
			for ((p = strtok(p, " ")); p; (p = strtok(0, " "))) {
				if (nsflags(p, &cflags, &flags) == -1) {
					free(buf);
					errno = EINVAL;
					return -1;
				}
			}
		}
	}

	return 0;
err:
	return -1;
}

int
newns(const char *namespaces, const char *nsfiles[])
{
	char newpath[PATH_MAX];
	char *buf, *p;
	uint64_t cflags, flags;
	int i, rv;

	for (p = *nsfile; *p; p++)
		if (nsfile(p, &cflags, &flags) == -1)
			return -1;

	buf = strdup(namespaces);
	for ((p = strtok(buf, " ")); p; (p = strtok(0, " "))) {
		if (nsflags(p, &cflags, &flags) == -1) {
			free(buf);
			errno = EINVAL;
			return -1;
		}
	}
	free(buf);

#if 0
	if (unshare(cflags) == -1)
		return -1;
#endif


	if (!root) {
		errno = EINVAL;
		return -1;
	}

	rv = mount(root->source, root->target, root->type, root->flags, root->data);
	if (rv == -1)
		return -1;

	struct nsmount *mp;
	for (mp = nsmount; nsmount; mp = mp->next) {
		snprintf(newpath, "%s/%s", nsdir, mp->target);
		if (mkdir(newpath) == -1)
			return -1;
		if (mount(mp->source, newpath, mp->type, mp->flags, mp->data) == -1)
			return -1;
	}

	return 0;
}
