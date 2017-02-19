#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#define _GNU_SOURCE /* for F_SETOWN */
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

union arg64 {
	struct {
		__u32 ENDIAN(lo32, hi32);
	};
	__u64 u64;
};

#define _LOAD_SYSCALL_NR \
	*fp++ = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _OFFSET_NR);

#define _LOAD_ARCH \
	*fp++ = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _OFFSET_ARCH)

#define _ARG32(idx) \
	*fp++ = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _LO_ARG(idx))

#define _ARG64(idx) \
	*fp++ = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _LO_ARG(idx)), \
	*fp++ = (struct sock_filter)BPF_STMT(BPF_ST, 0),                          \
	*fp++ = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _HI_ARG(idx)), \
	*fp++ = (struct sock_filter)BPF_STMT(BPF_ST, 1)

#define _JUMP_EQ(val, jt, jf) \
	*fp = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (val), (jt), (jf));\
	fp++

#define _JUMP_EQ64(val, jt, jf) \
	*fp = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((union arg64){.u64 = (val)}).hi32, 0, (jf)),           \
	fp++, \
	*fp++ = (struct sock_filter)BPF_STMT(BPF_LD+BPF_MEM, 0),    \
	*fp = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((union arg64){.u64 = (val)}).lo32, (jt), (jf)),\
	fp++

#define _JUMP(jmp) \
	*fp = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JA, (jmp), 0xFF, 0xFF),\
	fp++

#define _RET(x) \
	*fp++ = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, (x))

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

const uint64_t pledge_syscalls[] = {
	/**/
	[SYS_exit] = PLEDGE_ALWAYS,
	[SYS_exit_group] = PLEDGE_ALWAYS,
	[SYS_seccomp] = PLEDGE_ALWAYS,
	[SYS_prctl] = PLEDGE_ALWAYS | PLEDGE_PROC,

	[SYS_getuid] = PLEDGE_STDIO,
	[SYS_geteuid] = PLEDGE_STDIO,
	[SYS_getresuid] = PLEDGE_STDIO,
	[SYS_getgid] = PLEDGE_STDIO,
	[SYS_getegid] = PLEDGE_STDIO,
	[SYS_getresgid] = PLEDGE_STDIO,
	[SYS_getgroups] = PLEDGE_STDIO,
	[SYS_getpgrp] = PLEDGE_STDIO,
	[SYS_getpgid] = PLEDGE_STDIO,
	[SYS_getppid] = PLEDGE_STDIO,
	[SYS_getsid] = PLEDGE_STDIO,
	[SYS_getrlimit] = PLEDGE_STDIO,
	[SYS_gettimeofday] = PLEDGE_STDIO,
	[SYS_getrusage] = PLEDGE_STDIO,
	[SYS_clock_getres] = PLEDGE_STDIO,
	[SYS_clock_gettime] = PLEDGE_STDIO,
	[SYS_clock_nanosleep] = PLEDGE_STDIO,
	[SYS_getpid] = PLEDGE_STDIO,
	[SYS_uname] = PLEDGE_STDIO,
	[SYS_sysinfo] = PLEDGE_STDIO,
	[SYS_madvise] = PLEDGE_STDIO,
#if defined(SYS_fadvise64) && SYS_fadvise64 != SYS_fadvise
	[SYS_fadvise64] = PLEDGE_STDIO,
#endif
	[SYS_mmap] = PLEDGE_STDIO,
#if defined(SYS_mmap2)
	[SYS_mmap2] = PLEDGE_STDIO,
#endif
	[SYS_mprotect] = PLEDGE_STDIO,
	[SYS_munmap] = PLEDGE_STDIO,
	[SYS_msync] = PLEDGE_STDIO,
	[SYS_brk] = PLEDGE_STDIO,
	[SYS_umask] = PLEDGE_STDIO,
	[SYS_read] = PLEDGE_STDIO,
#if defined(SYS_read64) && SYS_read64 != SYS_read
	[SYS_read64] = PLEDGE_STDIO,
#endif
	[SYS_readv] = PLEDGE_STDIO,
#if defined(SYS_pread64) && SYS_pread64 != SYS_pread
	[SYS_pread64] = PLEDGE_STDIO,
#endif
	[SYS_preadv] = PLEDGE_STDIO,
	[SYS_write] = PLEDGE_STDIO,
#if defined(SYS_write64) && SYS_write64 != SYS_write
	[SYS_write64] = PLEDGE_STDIO,
#endif
#if defined(SYS_pwrite64) && SYS_pwrite64 != SYS_pwrite
	[SYS_pwrite64] = PLEDGE_STDIO,
#endif
	[SYS_writev] = PLEDGE_STDIO,
	[SYS_pwritev] = PLEDGE_STDIO,
	[SYS_recvmsg] = PLEDGE_STDIO,
	[SYS_recvfrom] = PLEDGE_STDIO,
	[SYS_ftruncate] = PLEDGE_STDIO,
	[SYS_futex] = PLEDGE_STDIO,
	[SYS_lseek] = PLEDGE_STDIO,
	[SYS_sendto] = PLEDGE_STDIO,
	[SYS_sendmsg] = PLEDGE_STDIO,
	[SYS_nanosleep] = PLEDGE_STDIO,
	[SYS_sigaltstack] = PLEDGE_STDIO,
	[SYS_rt_sigprocmask] = PLEDGE_STDIO,
	[SYS_rt_sigsuspend] = PLEDGE_STDIO,
	[SYS_rt_sigaction] = PLEDGE_STDIO,
	[SYS_rt_sigreturn] = PLEDGE_STDIO,
	[SYS_rt_sigpending] = PLEDGE_STDIO,
#ifdef SYS_sigreturn
	[SYS_sigreturn]
#endif
	[SYS_getitimer] = PLEDGE_STDIO,
	[SYS_setitimer] = PLEDGE_STDIO,
	[SYS_alarm] = PLEDGE_STDIO,
	[SYS_pause] = PLEDGE_STDIO,
	[SYS_time] = PLEDGE_STDIO,

	/* events,poll */
#ifdef SYS__newselect
	[SYS__newselect] = PLEDGE_STDIO,
#endif
	[SYS_epoll_create1] = PLEDGE_STDIO,
	[SYS_epoll_create] = PLEDGE_STDIO,
	[SYS_epoll_ctl] = PLEDGE_STDIO,
	[SYS_epoll_ctl_old] = PLEDGE_STDIO,
	[SYS_epoll_pwait] = PLEDGE_STDIO,
	[SYS_epoll_wait] = PLEDGE_STDIO,
	[SYS_epoll_wait_old] = PLEDGE_STDIO,
	[SYS_eventfd2] = PLEDGE_STDIO,
	[SYS_eventfd] = PLEDGE_STDIO,
	[SYS_poll] = PLEDGE_STDIO,
	[SYS_ppoll] = PLEDGE_STDIO,
	[SYS_pselect6] = PLEDGE_STDIO,
	[SYS_select] = PLEDGE_STDIO,

	[SYS_fstat] = PLEDGE_STDIO,
	[SYS_fsync] = PLEDGE_STDIO,
	[SYS_setsockopt] = PLEDGE_STDIO,
	[SYS_getsockopt] = PLEDGE_STDIO,
	[SYS_fcntl] = PLEDGE_STDIO,
	[SYS_close] = PLEDGE_STDIO,
	[SYS_tee] = PLEDGE_STDIO,
	[SYS_splice] = PLEDGE_STDIO,
	[SYS_dup] = PLEDGE_STDIO,
	[SYS_dup2] = PLEDGE_STDIO,
	[SYS_dup3] = PLEDGE_STDIO,
	[SYS_shutdown] = PLEDGE_STDIO,
	[SYS_fchdir] = PLEDGE_STDIO,
	[SYS_pipe] = PLEDGE_STDIO,
	[SYS_pipe2] = PLEDGE_STDIO,
	[SYS_socketpair] = PLEDGE_STDIO,
	[SYS_wait4] = PLEDGE_STDIO,
	[SYS_kill] = PLEDGE_STDIO,
	[SYS_ioctl] = PLEDGE_STDIO,
	[SYS_open] = PLEDGE_STDIO,
	[SYS_stat] = PLEDGE_STDIO,
#if defined(SYS_stat64) && SYS_stat64 != SYS_stat
	[SYS_stat64] = PLEDGE_STDIO,
#endif
	[SYS_access] = PLEDGE_STDIO,
	[SYS_readlink] = PLEDGE_STDIO,

	/* ipc */
	[SYS_memfd_create] = PLEDGE_IPC,
	[SYS_mq_getsetattr] = PLEDGE_IPC,
	[SYS_mq_notify] = PLEDGE_IPC,
	[SYS_mq_open] = PLEDGE_IPC,
	[SYS_mq_timedreceive] = PLEDGE_IPC,
	[SYS_mq_timedsend] = PLEDGE_IPC,
	[SYS_mq_unlink] = PLEDGE_IPC,
	[SYS_msgctl] = PLEDGE_IPC,
	[SYS_msgget] = PLEDGE_IPC,
	[SYS_msgrcv] = PLEDGE_IPC,
	[SYS_msgsnd] = PLEDGE_IPC,
	[SYS_process_vm_readv] = PLEDGE_IPC,
	[SYS_process_vm_writev] = PLEDGE_IPC,
	[SYS_semctl] = PLEDGE_IPC,
	[SYS_semget] = PLEDGE_IPC,
	[SYS_semop] = PLEDGE_IPC,
	[SYS_semtimedop] = PLEDGE_IPC,
	[SYS_shmat] = PLEDGE_IPC,
	[SYS_shmctl] = PLEDGE_IPC,
	[SYS_shmdt] = PLEDGE_IPC,
	[SYS_shmget] = PLEDGE_IPC,

	[SYS_adjtimex] = PLEDGE_SETTIME,
	[SYS_clock_adjtime] = PLEDGE_SETTIME,
	[SYS_clock_settime] = PLEDGE_SETTIME,
	[SYS_settimeofday] = PLEDGE_SETTIME,
#ifdef SYS_stime
	[SYS_stime] = PLEDGE_SETTIME,
#endif

	[SYS_chdir] = PLEDGE_RPATH,
	[SYS_openat] = PLEDGE_RPATH | PLEDGE_WPATH,
	[SYS_newfstatat] = PLEDGE_RPATH | PLEDGE_WPATH,
	[SYS_faccessat] = PLEDGE_RPATH | PLEDGE_WPATH,
	[SYS_getcwd] = PLEDGE_RPATH | PLEDGE_WPATH,
	[SYS_readlinkat] = PLEDGE_RPATH | PLEDGE_WPATH,
	[SYS_lstat] = PLEDGE_RPATH | PLEDGE_WPATH,
#if defined(SYS_lstat64) && SYS_lstat64 != SYS_lstat
	[SYS_lstat64] = PLEDGE_STDIO,
#endif
	[SYS_truncate] = PLEDGE_WPATH,
#if defined(SYS_truncate64) && SYS_truncate64 != SYS_truncate
	[SYS_truncate64] = PLEDGE_STDIO,
#endif
	[SYS_rename] = PLEDGE_RPATH | PLEDGE_CPATH,
	[SYS_rmdir] = PLEDGE_CPATH,
	[SYS_renameat] = PLEDGE_CPATH,
	[SYS_renameat2] = PLEDGE_CPATH,
	[SYS_link] = PLEDGE_CPATH,
	[SYS_linkat] = PLEDGE_CPATH,
	[SYS_lremovexattr] = PLEDGE_CPATH,
	[SYS_lsetxattr] = PLEDGE_CPATH,
	[SYS_symlink] = PLEDGE_CPATH,
	[SYS_unlink] = PLEDGE_CPATH,
	[SYS_unlinkat] = PLEDGE_CPATH,
	[SYS_mkdir] = PLEDGE_CPATH,
	[SYS_mkdirat] = PLEDGE_CPATH,

	[SYS_getdents] = PLEDGE_RPATH,
#if defined(SYS_getdents64) && SYS_getdents64 != SYS_getdents
	[SYS_getdents64] = PLEDGE_RPATH,
#endif
	[SYS_statfs] = PLEDGE_RPATH,
	[SYS_fstatfs] = PLEDGE_RPATH,
	[SYS_listxattr] = PLEDGE_RPATH,
	[SYS_llistxattr] = PLEDGE_RPATH,

	[SYS_utimes] = PLEDGE_FATTR,
	[SYS_utimensat] = PLEDGE_FATTR,
	[SYS_chmod] = PLEDGE_FATTR,
	[SYS_fchmod] = PLEDGE_FATTR,
	[SYS_fchmodat] = PLEDGE_FATTR,

	[SYS_chown] = PLEDGE_CHOWN,
	[SYS_fchownat] = PLEDGE_CHOWN,
	[SYS_lchown] = PLEDGE_CHOWN,
	[SYS_fchown] = PLEDGE_CHOWN,

	[SYS_arch_prctl] = PLEDGE_PROC,
	[SYS_clone] = PLEDGE_PROC,
	[SYS_fork] = PLEDGE_PROC,
	[SYS_setns] = PLEDGE_PROC,
	[SYS_setpgid] = PLEDGE_PROC,
	[SYS_setsid] = PLEDGE_PROC,
	[SYS_sched_get_priority_max] = PLEDGE_PROC,
	[SYS_sched_get_priority_min] = PLEDGE_PROC,
	[SYS_sched_getaffinity] = PLEDGE_PROC,
	[SYS_sched_getattr] = PLEDGE_PROC,
	[SYS_sched_getparam] = PLEDGE_PROC,
	[SYS_sched_getscheduler] = PLEDGE_PROC,
	[SYS_sched_rr_get_interval] = PLEDGE_PROC,
	[SYS_sched_setaffinity] = PLEDGE_PROC,
	[SYS_sched_setattr] = PLEDGE_PROC,
	[SYS_sched_setparam] = PLEDGE_PROC,
	[SYS_sched_setscheduler] = PLEDGE_PROC,
	[SYS_sched_yield] = PLEDGE_PROC,
	[SYS_set_tid_address] = PLEDGE_PROC,
	[SYS_set_robust_list] = PLEDGE_PROC,
	[SYS_get_robust_list] = PLEDGE_PROC,
	[SYS_unshare] = PLEDGE_PROC,
	[SYS_vfork] = PLEDGE_PROC,

	[SYS_setrlimit] = PLEDGE_PROC | PLEDGE_ID,
	[SYS_prlimit64] = PLEDGE_PROC | PLEDGE_ID,
	[SYS_getpriority] = PLEDGE_PROC | PLEDGE_ID,
	[SYS_setpriority] = PLEDGE_PROC | PLEDGE_ID,

	[SYS_setuid] = PLEDGE_ID,
	[SYS_setreuid] = PLEDGE_ID,
	[SYS_setresuid] = PLEDGE_ID,
	[SYS_setgid] = PLEDGE_ID,
	[SYS_setregid] = PLEDGE_ID,
	[SYS_setresgid] = PLEDGE_ID,
	[SYS_setgroups] = PLEDGE_ID,

	[SYS_execve] = PLEDGE_EXEC,
	[SYS_execveat] = PLEDGE_EXEC,

	[SYS_socket] = PLEDGE_INET | PLEDGE_UNIX,
	[SYS_connect] = PLEDGE_INET | PLEDGE_UNIX,
	[SYS_bind] = PLEDGE_INET | PLEDGE_UNIX,
	[SYS_getsockname] = PLEDGE_INET | PLEDGE_UNIX,

	[SYS_listen] = PLEDGE_INET | PLEDGE_UNIX,
	[SYS_accept4] = PLEDGE_INET | PLEDGE_UNIX,
	[SYS_accept] = PLEDGE_INET | PLEDGE_UNIX,
	[SYS_getpeername] = PLEDGE_INET | PLEDGE_UNIX,

	[SYS_flock] = PLEDGE_FLOCK,

	[SYS_modify_ldt] = PLEDGE_EMUL,
#ifdef SYS_subpage_prot
	[SYS_subpage_prot] = PLEDGE_EMUL,
#endif
#ifdef SYS_switch_edian
	[SYS_switch_edian] = PLEDGE_EMUL,
#endif
#ifdef SYS_vm86
	[SYS_vm86] = PLEDGE_EMUL,
#endif
#ifdef SYS_vm86old
	[SYS_vm86old] = PLEDGE_EMUL,
#endif

	[SYS_chroot] = PLEDGE_MOUNT,
	[SYS_mount] = PLEDGE_MOUNT,
	[SYS_pivot_root] = PLEDGE_MOUNT,
	[SYS_swapoff] = PLEDGE_MOUNT,
	[SYS_swapon] = PLEDGE_MOUNT,
	[SYS_umount2] = PLEDGE_MOUNT,
#ifdef SYS_umount
	[SYS_umount] = PLEDGE_MOUNT,
#endif

	[SYS_add_key] = PLEDGE_KEY,
	[SYS_keyctl] = PLEDGE_KEY,
	[SYS_request_key] = PLEDGE_KEY,

	[SYS_delete_module] = PLEDGE_KERN,
	[SYS_finit_module] = PLEDGE_KERN,
	[SYS_init_module] = PLEDGE_KERN,
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
	for (i = 0; i < num; i++) {
		_JUMP_EQ(calls[i], _END, 0);
	}
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
	for (i = 0; i < num; i++) {
		_JUMP_EQ(calls[i], _END, 0);
	}
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

#ifdef TEST
	printf("allowsocket %d unix=%d inet=%d\n", allow_socket,
	    ((flags&PLEDGE_UNIX) == PLEDGE_UNIX),
	    ((flags&PLEDGE_INET) == PLEDGE_INET));
	printf("allowselfchown %d\n", allow_selfchown);
	printf("allowprctl %d\n", allow_prctl);
	printf("allowselfkill %d\n", allow_selfkill);
	printf("allowfcntl %d\n", allow_fcntl);
	printf("allowbasicioctl %d\n", allow_ioctl);
#endif

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
		_JUMP_EQ(SYS_fcntl, 0, 2);
		_ARG32(1);
		_JUMP_EQ(F_SETOWN, _EPERM, _ALLOW);
	}

	if (allow_selfkill) {
		pid_t pid = getpid();
		/* allow kill(0 | getpid(), ...) */
		_JUMP_EQ(SYS_kill, 0, 10); // XXX: fix offset
		_ARG64(0); // +4
		_JUMP_EQ64(0, _ALLOW, 0); // +3
		_JUMP_EQ64(pid, _ALLOW, _EPERM); // +3
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
