#include <stdint.h>

enum {
	PLEDGED		= 0x100000,
	PLEDGE_ALWAYS	= 0xffffff,
	PLEDGE_IOCTL	= 0x000001,
	PLEDGE_RPATH	= 0x000002,
	PLEDGE_WPATH	= 0x000004,
	PLEDGE_CPATH	= 0x000008,
	PLEDGE_STDIO	= 0x000010,
	PLEDGE_CHOWN	= 0x000020,
	PLEDGE_DPATH	= 0x000040,
	PLEDGE_DRM	= 0x000080,
	PLEDGE_EXEC	= 0x000100,
	PLEDGE_FATTR	= 0x000200,
	PLEDGE_FLOCK	= 0x000400,
	PLEDGE_GETPW	= 0x000800,
	PLEDGE_INET	= 0x001000,
	PLEDGE_PROC	= 0x002000,
	PLEDGE_ID	= 0x004000,
	PLEDGE_SETTIME	= 0x008000,
	PLEDGE_UNIX	= 0x010000,
	PLEDGE_CHOWNUID	= 0x020000,
	PLEDGE_DEBUG	= 0x040000,
	PLEDGE_VERBOSE	= 0x080000,
};

struct sock_fprog *pledge_whitelist(uint64_t);
struct sock_fprog *pledge_blacklist(uint64_t, uint64_t);
struct sock_fprog *pledge_filter(uint64_t, uint64_t);
uint64_t pledge_flags(const char *);
int pledge(const char *, const char *[]);
