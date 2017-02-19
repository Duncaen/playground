#include <stdint.h>
#include <stdio.h>

#include "pledge.h"

#define TEST(s, o, f, t, e) do { \
	oldflags = (o); flags = (f); \
	((rv = (t)) == (e) ? pass++ : fail++); \
	printf("%s:%d: %-7s ", __FILE__, __LINE__, (s)); \
	printf("%d %s %d%s\n", (e), (rv == (e)) ? "==" : "!=",  rv, (rv != (e)) ? " <<<<<" : ""); \
} while(0)


int
main()
{
	uint64_t flags, oldflags;
	int rv, fail, pass;
	fail = pass = 0;

	TEST("chown", PLEDGE_CHOWNUID, 0LLU, _FILTER_CHOWN, 1);
	TEST("chown", 0LLU, 0LLU, _FILTER_CHOWN, 1);
	TEST("chown", PLEDGE_CHOWNUID, PLEDGE_CHOWNUID, _FILTER_CHOWN, 0);
	TEST("chown", PLEDGED, 0LLU, _FILTER_CHOWN, 0);
	TEST("chown", 0LLU, PLEDGE_CHOWNUID, _FILTER_CHOWN, 0);

	TEST("prctl", PLEDGE_PROC, 0LLU, _FILTER_PRCTL, 1);
	TEST("prctl", PLEDGE_PROC, PLEDGE_PROC, _FILTER_PRCTL, 0);
	TEST("prctl", 0LLU, 0LLU, _FILTER_PRCTL, 0);

	TEST("socket", PLEDGE_INET|PLEDGE_UNIX, PLEDGE_UNIX, _FILTER_SOCKET, 1);
	TEST("socket", PLEDGE_INET|PLEDGE_UNIX, PLEDGE_INET, _FILTER_SOCKET, 1);
	TEST("socket", 0LLU, PLEDGE_INET, _FILTER_SOCKET, 1);
	TEST("socket", 0LLU, PLEDGE_UNIX|PLEDGE_INET, _FILTER_SOCKET, 0);
	TEST("socket", PLEDGE_INET, PLEDGE_INET, _FILTER_SOCKET, 0);
	TEST("socket", PLEDGE_UNIX, PLEDGE_UNIX, _FILTER_SOCKET, 0);
	TEST("socket", PLEDGE_INET|PLEDGE_UNIX, PLEDGE_INET|PLEDGE_UNIX, _FILTER_SOCKET, 0);
	TEST("socket", 0LLU, 0LLU, _FILTER_SOCKET, 0);

	TEST("kill", PLEDGE_PROC, 0LLU, _FILTER_KILL, 1);
	TEST("kill", 0LLU, 0LLU, _FILTER_KILL, 1);
	TEST("kill", PLEDGE_PROC, PLEDGE_PROC, _FILTER_KILL, 0);
	TEST("kill", 0LLU, PLEDGE_PROC, _FILTER_KILL, 0);

	TEST("fcntl", 0LLU, 0LLU, _FILTER_FCNTL, 1);
	TEST("fcntl", PLEDGE_PROC, 0LLU, _FILTER_FCNTL, 1);
	TEST("fcntl", PLEDGE_PROC, PLEDGE_PROC, _FILTER_FCNTL, 0);

	TEST("fcntl", 0LLU, 0LLU, _FILTER_FCNTL, 1);
	TEST("fcntl", PLEDGE_PROC, 0LLU, _FILTER_FCNTL, 1);
	TEST("fcntl", PLEDGE_PROC, PLEDGE_PROC, _FILTER_FCNTL, 0);

	TEST("ioctl", 0LLU, 0LLU, _FILTER_IOCTL_ALWAYS, 1);
	TEST("ioctl", 0LLU, PLEDGE_IOCTL, _FILTER_IOCTL_ALWAYS, 1);
	TEST("ioctl", PLEDGE_IOCTL, PLEDGE_IOCTL, _FILTER_IOCTL_ALWAYS, 0);

	printf("failed=%d passed=%d\n", fail, pass);

	return (fail ? 1 : 0);
}
