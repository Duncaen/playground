#define _OFFSET_NR		offsetof(struct seccomp_data, nr)
#define _OFFSET_ARCH		offsetof(struct seccomp_data, arch)
#define _OFFSET_ARG(idx) 	offsetof(struct seccomp_data, args[(idx)])

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
	struct byteorder {
		__u32 ENDIAN(lo, hi);
	} u32;
	__u64 u64;
};

#define _LOAD_SYSCALL_NR do {                                                  \
	*fp = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _OFFSET_NR);  \
	fp++;                                                                  \
} while (0)

#define _LOAD_ARCH do {                                                        \
	*fp = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _OFFSET_ARCH);\
	fp++;                                                                  \
} while (0)

#define _ARG32(idx) do {                                                       \
	*fp = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _LO_ARG(idx));\
	fp++;                                                                  \
} while (0)

#define _ARG64(idx) do {                                                       \
	*fp = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _LO_ARG(idx));\
	fp++;                                                                  \
	*fp = (struct sock_filter)BPF_STMT(BPF_ST, 0);                         \
	fp++;                                                                  \
	*fp = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, _HI_ARG(idx));\
	fp++;                                                                  \
	*fp = (struct sock_filter)BPF_STMT(BPF_ST, 1);                         \
	fp++;                                                                  \
} while (0)

#define _JUMP_EQ(v, t, f) do {                                                 \
	*fp = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,              \
	    (v), (t), (f));                                                    \
	fp++;                                                                  \
} while (0)

#define _JUMP_EQ64(val, jt, jf) do {                                           \
	*fp = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,              \
	    ((union arg64){.u64 = (val)}).u32.hi, 0, (jf));                    \
	fp++;                                                                  \
	*fp = (struct sock_filter)BPF_STMT(BPF_LD+BPF_MEM, 0);                 \
	fp++;                                                                  \
	*fp = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,              \
	    ((union arg64){.u64 = (val)}).u32.lo, (jt), (jf));                 \
	fp++;                                                                  \
} while (0)

#define _JUMP(j) do {                                                          \
	*fp = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JA, (j), 0xFF, 0xFF),   \
	fp++;                                                                  \
} while (0)

#define _RET(v) do {                                                           \
	*fp = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, (v));                \
	fp++;                                                                  \
} while (0)

#define _END	len-1-(fp-fprog->filter)-1
