#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <endian.h>

#include <asm/bitsperlong.h>	/* for __BITS_PER_LONG */

#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#include "pledge.h"
#include "pledge_syscalls.h"

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

#define _OFFSET_NR 0
#define _OFFSET_ARCH _OFFSET_NR + sizeof(int)
#define _OFFSET_IP _OFFSET_ARCH + sizeof(__u32)
#define _OFFSET_ARG(idx) _OFFSET_IP + (sizeof(__u32) * (idx))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define _LO_ARG(idx) \
	_OFFSET_ARG((idx))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define _LO_ARG(idx) \
	_OFFSET_ARG((idx)) + sizeof(__u32)
#else
#error "Unknown endianness"
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define ENDIAN(_lo, _hi) _lo, _hi
# define _HI_ARG(idx) \
	_OFFSET_ARG((idx)) + sizeof(__u32)
#elif __BYTE_ORDER == __BIG_ENDIAN
# define ENDIAN(_lo, _hi) _hi, _lo
# define _HI_ARG(idx) \
	_OFFSET_ARG((idx))
#else
# error "Unknown endianness"
#endif

/*
union arg64 {
	struct edi {
		__u32 ENDIAN(lo, hi);
	} u32;
	__u64 u64;
};
*/

union arg64 {
	struct {
		__u32 ENDIAN(lo32, hi32);
	};
	__u64 u64;
};

#define _LOAD_SYSCALL_NR do {                                               \
		*fp = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _OFFSET_NR);   \
		fp++;                                                                   \
} while (0)

#define _LOAD_ARCH do {                                                     \
		*fp = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _OFFSET_ARCH); \
		fp++;                                                                   \
	} while (0)

#define _ARG32(idx) do {                                                    \
		*fp = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _LO_ARG(idx)); \
		fp++;                                                                   \
	} while (0)

#define _ARG64(idx) do {                                                    \
		*fp = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _LO_ARG(idx)); \
		fp++;                                                                   \
		*fp = (struct sock_filter)BPF_STMT(BPF_ST, 0);                          \
		fp++;                                                                   \
		*fp = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _HI_ARG(idx)); \
		fp++;                                                                   \
		*fp = (struct sock_filter)BPF_STMT(BPF_ST, 1);                          \
		fp++;                                                                   \
	} while (0)

#define _JUMP_EQ(v, t, f) do {                                                \
		*fp = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (v), (t), (f)); \
		fp++;                                                                     \
	} while (0)

#define _JUMP_EQ64(val, jt, jf) do {                                       \
		*fp = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,              \
		               ((union arg64){.u64 = (val)}).hi32, 0, (jf));           \
		fp++;                                                                  \
		*fp = (struct sock_filter)BPF_STMT(BPF_LD+BPF_MEM, 0);                 \
		fp++;                                                                  \
		*fp = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,              \
				((union arg64){.u64 = (val)}).lo32, (jt), (jf));                   \
		fp++;                                                                  \
	} while (0)

#define _JUMP(j) do {                                                       \
		*fp = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JA, (j), 0xFF, 0xFF),    \
		fp++;                                                                   \
	} while (0)

#define _RET(v) do {                                                        \
		*fp = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, (v));                 \
		fp++;                                                                   \
	} while (0)

#define _END \
	len-1-(fp-fprog->filter)-1

struct promise {
	char *name;
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
	int allow_prctl, allow_socket, allow_selfkill, allow_fcntl, allow_selfchown, allow_ioctl;

	len = 0;
	allow_selfchown = (!(flags & PLEDGE_CHOWNUID) && (flags & PLEDGE_CHOWN)) || 0;
	allow_prctl = !(flags & PLEDGE_PROC) || 0;
	allow_socket = (flags & PLEDGE_INET) || (flags & PLEDGE_UNIX) || 0;
	allow_selfkill = (!(flags & PLEDGE_PROC)) || 0;
	allow_fcntl = (!(flags & PLEDGE_PROC) && (flags & PLEDGE_STDIO)) || 0;
	allow_ioctl = (!(flags & PLEDGE_IOCTL)) || 0;

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

	if (allow_ioctl)
		len += 6;

	/* no new filters */
	if (!len)
		return 0;

	/* space for 3 different return statements (KILL,ALLOW,EPERM) */
	len += 3;

	printf("allowsocket %d unix=%d inet=%d\n", allow_socket,
	    ((flags&PLEDGE_UNIX) == PLEDGE_UNIX),
	    ((flags&PLEDGE_INET) == PLEDGE_INET));
	printf("allowselfchown %d\n", allow_selfchown);
	printf("allowprctl %d\n", allow_prctl);
	printf("allowselfkill %d\n", allow_selfkill);
	printf("allowfcntl %d\n", allow_fcntl);
	printf("allowbasicioctl %d\n", allow_ioctl);

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

	if (allow_selfkill) {
		pid_t pid = getpid();
		/* allow kill(0 | getpid(), ...) */
		_JUMP_EQ(SYS_kill, _KILL, 10); // XXX: fix offset
		_ARG64(0); // +4
		_JUMP_EQ64(0, _KILL, _KILL); // +3
		_JUMP_EQ64(pid, _KILL, _KILL); // +3
	}


	if (allow_selfchown) {
		uid_t uid = getuid();
		gid_t gid = getgid();

		/* chown(2), fchown(2), lchown(2) */
		_JUMP_EQ(SYS_chown, 3, 0);
		_JUMP_EQ(SYS_fchown, 2, 0);
		_JUMP_EQ(SYS_lchown, 0, 14); // XXX: fix offset
		_ARG64(1); // +4
		_JUMP_EQ64(uid, 0, _EPERM); // +3
		_ARG64(2); // + 4
		_JUMP_EQ64(gid, _ALLOW, _EPERM); // +3

	/* fchownat(2) */
		_JUMP_EQ(SYS_fchownat, 0, 14); // XXX: fix offset
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
		_JUMP_EQ(SYS_fcntl, 0, 1);
		_ARG32(1);
		_JUMP_EQ(F_SETOWN, _EPERM, _ALLOW);
	}

	if (allow_ioctl) {
		/* allow ioctl(..., FIONREAD|FIONBIO|FIOCLEX|FIONCLEX, ...) */
		_JUMP_EQ(SYS_kill, 0, 5);
		_ARG32(1);
		_JUMP_EQ(FIONREAD, _ALLOW, 0);
		_JUMP_EQ(FIONBIO, _ALLOW, 0);
		_JUMP_EQ(FIOCLEX, _ALLOW, 0);
		_JUMP_EQ(FIONCLEX, _ALLOW, _KILL);
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

#ifdef TEST
int
main(int argc, char *argv[])
{
	if (pledge("stdio chown fattr cpath proc id", 0) == -1) {
		fprintf(stderr, "error: pledge\n");
		exit(1);
	}

	if (argc == 2) {
		if (pledge("stdio", 0) == -1) {
			fprintf(stderr, "error: pledge\n");
			exit(1);
		}
		printf("block chown\n");
		chown("./test", 1000, 1000);
	} else if (argc == 3) {
		printf("allow unlink\n");
		unlink("./test");
	} else if (argc == 4) {
		if (pledge("stdio", 0) == -1) {
			fprintf(stderr, "error: pledge\n");
			exit(1);
		}
		printf("block unlink\n");
		unlink("./test");
	} else if (argc == 5) {
#ifdef getentropy
		printf("block getrandom\n");
		char buf[128];
		getentropy(buf, sizeof buf);
#endif
	} else if (argc == 6) {
		if (pledge("stdio foo", 0) == -1) {
			fprintf(stderr, "error: pledge\n");
			exit(1);
		}
	} else if (argc == 7) {
		fprintf(stderr, "test chown(.., 1001, 1001)\n");
		chown("./test", 1001, 1001);
	} else {
		printf("allow\n");
	}
	return 0;
}
#endif
