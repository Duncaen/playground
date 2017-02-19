const uint64_t pledge_syscalls[] = {
	/**/
	[SYS_exit] = PLEDGE_ALWAYS,
	[SYS_exit_group] = PLEDGE_ALWAYS,
	[SYS_seccomp] = PLEDGE_ALWAYS,
	[SYS_prctl] = PLEDGE_ALWAYS | PLEDGE_PROC,

	[SYS_arch_prctl] = PLEDGE_STDIO,
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
#ifdef SYS_getrandom
	[SYS_getrandom] = PLEDGE_STDIO,
#endif
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
	[SYS_set_tid_address] = PLEDGE_STDIO,
	[SYS_gettid] = PLEDGE_STDIO,
	[SYS_tgkill] = PLEDGE_STDIO,

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
