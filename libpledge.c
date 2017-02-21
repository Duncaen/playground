#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <asm/bitsperlong.h>	/* for __BITS_PER_LONG */

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "pledge.h"
#include "pledge_syscalls.h"
#include "seccomp_bpf_utils.h"

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

struct promise {
	const char *name;
	uint64_t flags;
};

static const struct promise strpromises[] = {
	{ "chown",	PLEDGE_CHOWN | PLEDGE_CHOWNUID },
	{ "cpath",	PLEDGE_CPATH },
	{ "dpath",	PLEDGE_DPATH },
	{ "drm",	PLEDGE_DRM },
	{ "exec",	PLEDGE_EXEC },
	{ "fattr",	PLEDGE_FATTR | PLEDGE_CHOWN },
	{ "flock",	PLEDGE_FLOCK },
	{ "getpw",	PLEDGE_GETPW },
	{ "id",		PLEDGE_ID },
	{ "inet",	PLEDGE_INET },
	{ "ioctl",	PLEDGE_IOCTL },
	{ "proc",	PLEDGE_PROC },
	{ "rpath",	PLEDGE_RPATH },
	{ "settime",	PLEDGE_SETTIME },
	{ "stdio",	PLEDGE_STDIO },
	{ "unix",	PLEDGE_UNIX },
	{ "wpath",	PLEDGE_WPATH },
	{ "debug",	PLEDGE_DEBUG },
	{ "verbose",	PLEDGE_VERBOSE },
	{ "ipc",	 PLEDGE_IPC },
	{ "emul",	 PLEDGE_EMUL },
	{ "mount",	 PLEDGE_MOUNT },
	{ "key",	 PLEDGE_KEY },
	{ "kern",	 PLEDGE_KERN },
	{ 0, 0 },
};


struct sock_fprog *
pledge_whitelist(uint64_t flags)
{
	uint64_t len, num, i;
	uint64_t calls[nitems(pledge_syscalls)];
	struct sock_fprog *fprog;
	struct sock_filter *fp;

	num = 0;

	for (i = 0; i < nitems(pledge_syscalls); i++) {
		if (!(flags & pledge_syscalls[i]))
			continue;
		calls[num++] = i;
#ifndef NOVERBOSE
		if (flags & PLEDGE_VERBOSE)
			fprintf(stderr, "whitelist syscall %ld\n", i);
#endif
	}

	/* space for all syscall comparisons */
	len = num;
	/* space arch validation, syscall load and and two return statements */
	len += 5;

	if (!(fprog = calloc(1, sizeof(struct sock_fprog))))
		return 0;
	if (!(fprog->filter = calloc(len, sizeof(struct sock_filter)))) {
		free(fprog);
		return 0;
	}
	fprog->len = len;
	fp = fprog->filter;

	/* validate architecture, jump to the RET_KILL if not equal */
	_LOAD_ARCH;
	_JUMP_EQ(AUDIT_ARCH_X86_64, 0, _END-1);
	/* compare syscall numbers */
	_LOAD_SYSCALL_NR;
	for (i = 0; i < num; i++)
		_JUMP_EQ(calls[i], _END, 0);
	/* no match */
#ifndef NODEBUG
	_RET((flags & PLEDGE_DEBUG) ? SECCOMP_RET_TRAP : SECCOMP_RET_KILL);
#else
	_RET(SECCOMP_RET_KILL);
#endif
	/* matching syscall jump here */
	_RET(SECCOMP_RET_ALLOW);

	return fprog;
}

struct sock_fprog *
pledge_blacklist(uint64_t flags, uint64_t oldflags)
{
	uint64_t len, num, i;
	uint64_t calls[nitems(pledge_syscalls)];
	struct sock_fprog *fprog;
	struct sock_filter *fp;

	num = 0;

	for (i = 0; i < nitems(pledge_syscalls); i++) {
		if (!pledge_syscalls[i])
			continue;
		if ((flags & pledge_syscalls[i]) || !(oldflags & pledge_syscalls[i]))
			continue;
		calls[num++] = i;
#ifndef NOVERBOSE
		if (flags & PLEDGE_VERBOSE)
			fprintf(stderr, "blacklist syscall %ld\n", i);
#endif
	}

	/* no new rules to apply */
	if (!num)
		return 0;

	/* space for all syscall comparisons */
	len = num;
	/* syscall load and and two return statements */
	len += 3;

	if (!(fprog = calloc(1, sizeof(struct sock_fprog))))
		return 0;
	if (!(fprog->filter = calloc(len, sizeof(struct sock_filter)))) {
		free(fprog);
		return 0;
	}
	fprog->len = len;
	fp = fprog->filter;

	/* compare all syscall numbers */
	_LOAD_SYSCALL_NR;
	for (i = 0; i < num; i++)
		_JUMP_EQ(calls[i], _END, 0);
	/* no match */
	_RET(SECCOMP_RET_ALLOW);
	/* matching syscall jump here */
#ifndef NODEBUG
	_RET((flags & PLEDGE_DEBUG) ? SECCOMP_RET_TRAP : SECCOMP_RET_KILL);
#else
	_RET(SECCOMP_RET_KILL);
#endif

	return fprog;
}

struct sock_fprog *
pledge_filter(uint64_t flags, uint64_t oldflags)
{
	struct sock_fprog *fprog;
	struct sock_filter *fp;
	uint64_t len;
	int allow_prctl, allow_socket, allow_selfkill, allow_fcntl, allow_selfchown, allow_ioctl_always, allow_ioctl_ioctl;
	int filter_open;

	len = 0;

	allow_selfchown = _FILTER_CHOWN;
	allow_prctl = _FILTER_PRCTL;
	allow_socket = _FILTER_SOCKET;
	allow_selfkill = _FILTER_KILL;
	allow_fcntl = _FILTER_FCNTL;
	allow_ioctl_always = _FILTER_IOCTL_ALWAYS;
	allow_ioctl_ioctl= _FILTER_IOCTL_IOCTL;
	filter_open = _FILTER_OPEN;

	if (filter_open)
		len += 9;

	/* chown(2), fchown(2), lchown(2), fchownat(2) */
	if (allow_selfchown)
		len += 32;

	if (allow_prctl)
		len += 4;

	if (allow_socket) {
		len += 3;
		/* AF_INET[6]? */
		if ((flags&PLEDGE_INET))
			len += 2;
		/* AF_UNIX */
		if ((flags&PLEDGE_UNIX))
			len += 1;
	}

	if (allow_selfkill)
		len += 11;

	if (allow_fcntl)
		len += 3;

	if (allow_ioctl_always || allow_ioctl_ioctl) {
		len += 6;
		if (allow_ioctl_always)
			len += 12;
		if (allow_ioctl_ioctl)
			len += 21;
	}

	/* no new filters */
	if (!len)
		return 0;

	/* space for 3 different return statements (KILL,ALLOW,EPERM) */
	len += 4;

	printf("allowsocket %d unix=%d inet=%d\n", allow_socket,
	    ((flags&PLEDGE_UNIX) == PLEDGE_UNIX),
	    ((flags&PLEDGE_INET) == PLEDGE_INET));
	printf("allowselfchown %d\n", allow_selfchown);
	printf("allowprctl %d\n", allow_prctl);
	printf("allowselfkill %d\n", allow_selfkill);
	printf("allowfcntl %d\n", allow_fcntl);
	printf("allow ioctl always %d\n", allow_ioctl_always);
	printf("allow ioctl ioctl %d\n", allow_ioctl_ioctl);
	printf("filter open %d\n", filter_open);

	if (!(fprog = calloc(1, sizeof(struct sock_fprog))))
		return 0;
	if (!(fprog->filter = calloc(len, sizeof(struct sock_filter)))) {
		free(fprog);
		return 0;
	}
	fprog->len = len;
	fp = fprog->filter;

#define _KILL		_END
#define _EPERM	_END-1
#define _ALLOW	_END-2

	_LOAD_SYSCALL_NR;

	if (filter_open) {
		/* allow kill(0 | getpid(), ...) */
		_JUMP_EQ(SYS_open, 0, 8);
		_ARG32(1);
		_JUMP_SET(O_RDWR, _EPERM, 0);
		_JUMP_SET(O_WRONLY, _EPERM, 0);
		_JUMP_SET(O_APPEND, _EPERM, 0);
		_JUMP_SET(O_CREAT, _EPERM, 0);
		/* O_TMPFILE and O_DIRECTORY conflict... */
		/* _JUMP_SET(O_TMPFILE, _EPERM, 0); */
		_JUMP_SET(O_TRUNC, _EPERM, 0);
		_JUMP_SET(O_TRUNC, _EPERM, 0);
		_LOAD_SYSCALL_NR;
	}

	if (allow_selfkill) {
		pid_t pid = getpid();
		/* allow kill(0 | getpid(), ...) */
		_JUMP_EQ(SYS_kill, 0, 10); // XXX: fix offset
		_ARG64(0); // +4
		_JUMP_EQ64(0, _ALLOW, 0); // +3
		_JUMP_EQ64(pid, _ALLOW, _EPERM); // +3
	}

	if (allow_selfchown) {
		uid_t uid = getuid();
		gid_t gid = getgid();

		/* chown(2), fchown(2), lchown(2) */
		_JUMP_EQ(SYS_chown, 4, 0);
		_JUMP_EQ(SYS_fchown, 3, 0);
		_JUMP_EQ(SYS_lchown, 2, 0); // XXX: fix offset
		_JUMP_EQ(SYS_fchownat, 14, 28); // XXX: fix offset

		/* [fl]chown(.., uid, gid) */
		_ARG64(1); // +4
		_JUMP_EQ64(uid, 0, _EPERM); // +3
		_ARG64(2); // + 4
		_JUMP_EQ64(gid, _ALLOW, _EPERM); // +3

	/* fchownat(.., .., uid, gid, ..) */
		_ARG64(2); // +4
		_JUMP_EQ64(uid, 0, _EPERM); // +3
		_ARG64(4); // + 4
		_JUMP_EQ64(gid, _ALLOW, _EPERM); // +3
	}

	if (allow_prctl) {
		/* allow prctl(PR_[SG]ET_SECCOMP, ...) */
		_JUMP_EQ(SYS_prctl, 0, 3);
		_ARG32(0);
		_JUMP_EQ(PR_SET_SECCOMP, _ALLOW, 0);
		_JUMP_EQ(PR_GET_SECCOMP, _ALLOW, _KILL);
	}

	if (allow_socket) {
		/* allow specific domains: socket(domain, .., ..)  */
		_JUMP_EQ(SYS_socket, 0, 2 + ((flags & PLEDGE_INET) ? 2 : 0) + ((flags & PLEDGE_UNIX) ? 1 : 0));
		_ARG32(0);
		if (flags & PLEDGE_INET) {
			_JUMP_EQ(AF_INET, _ALLOW, 0);
			_JUMP_EQ(AF_INET6, _ALLOW, 0);
		}
		if (flags & PLEDGE_UNIX) {
			_JUMP_EQ(AF_UNIX, _ALLOW, 0);
		}
		_JUMP(_EPERM);
	}

	if (allow_fcntl) {
		/* allow fcntl(..., != F_SETOWN, ...) */
		_JUMP_EQ(SYS_fcntl, 0, 2);
		_ARG32(1);
		_JUMP_EQ(F_SETOWN, _EPERM, _ALLOW);
	}

	if (allow_ioctl_always || allow_ioctl_ioctl) {
		/* allow ioctl(..., FIONREAD|FIONBIO|FIOCLEX|FIONCLEX, ...) */
		_JUMP_EQ(SYS_ioctl, 0, 5 +
		    (allow_ioctl_always ? 12 : 0) +
		    (allow_ioctl_ioctl ? 21 : 0));
		_ARG64(1); // 4
		if (allow_ioctl_always) {
			_JUMP_EQ64(FIONREAD, _ALLOW, 0);
			_JUMP_EQ64(FIONBIO, _ALLOW, 0);
			_JUMP_EQ64(FIOCLEX, _ALLOW, 0);
			_JUMP_EQ64(FIONCLEX, _ALLOW, 0);
		}
		if (allow_ioctl_ioctl) {
#define _JTRUE	(allow_ioctl_ioctl == FILTER_WHITELIST ? _ALLOW : _EPERM)
			_JUMP_EQ64(TCFLSH, _JTRUE, 0);
			_JUMP_EQ64(TCGETS, _JTRUE, 0);
			_JUMP_EQ64(TIOCGWINSZ, _JTRUE, 0);
			_JUMP_EQ64(TIOCGPGRP, _JTRUE, 0);
			_JUMP_EQ64(TIOCSPGRP, _JTRUE, 0);
			_JUMP_EQ64(TCSETSF, _JTRUE, 0);
			_JUMP_EQ64(TCSETSW, _JTRUE, 0);
		}
		_JUMP(_EPERM);
	}

	/* no match */
	_RET(SECCOMP_RET_ALLOW);
	/* no permissions */
	_RET(SECCOMP_RET_ERRNO|(EPERM & SECCOMP_RET_DATA));
	/* matching syscall jump here */
#ifndef NODEBUG
	_RET((flags & PLEDGE_DEBUG) ? SECCOMP_RET_TRAP : SECCOMP_RET_KILL);
#else
	_RET(SECCOMP_RET_KILL);
#endif

	printf("length=%ld expected=%ld\n", (fp-fprog->filter), len);

	return fprog;
}

uint64_t
pledge_flags(const char *promises)
{
	uint64_t flags, f;
	const struct promise *pp;
	char *buf, *p;

	flags = 0;
	buf = strdup(promises);
	for ((p = strtok(buf, " ")); p; (p = strtok(0, " "))) {
		f = 0;
		for (pp = strpromises; pp->name; pp++) {
			if (strcmp(p, pp->name) == 0)
				f = pp->flags;
		}
		if (!f) {
			free(buf);
			return 0;
		}
		flags |= f;
	}
	free(buf);
	return flags;
}

static uint64_t currflags = 0;

int
pledge(const char *promises, const char *paths[])
{
	struct sock_fprog *filterprog;
	uint64_t flags;
	int rv = 0;

	if (paths) {
		errno = EINVAL;
		return -1;
	}

	if (!promises)
		return 0;

	if (!(flags = pledge_flags(promises))) {
		errno = EINVAL;
		return -1;
	}

	if ((currflags & PLEDGED) != PLEDGED) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
			return -1;
		filterprog = pledge_whitelist(flags);
	} else {
		filterprog = pledge_blacklist(flags, currflags);
	}

	if (filterprog) {
		if ((rv = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, filterprog)) == -1)
			goto ret;
		free(filterprog);
	}

	if ((filterprog = pledge_filter(flags, currflags)))
		if ((rv = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, filterprog)) == -1)
			goto ret;

	currflags = flags | PLEDGED;

ret:
	free(filterprog);
	return rv;
}
