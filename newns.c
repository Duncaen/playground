#define _GNU_SOURCE	/* for CLONE_* */
#include <err.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static char *argv0;

static void
usage()
{
	fprintf(stderr, "usage: %s [-c dir] [-b new:old] [-n namespace] [command] [args]\n", argv0);
	exit(1);
}

static int
write_map(const char *file, unsigned int start, unsigned int end)
{
	char buf[32];
	int fd, rv;
	rv = 0;
	if ((fd = open(file, O_RDWR)) == -1)
		return 1;
	if (write(fd, buf, snprintf(buf, sizeof buf, "%u %u 1", start, end)) == -1)
		rv = 1;
	close(fd);
	return rv;
}

int
main(int argc, char **argv)
{
	char opt;
	char *nsfile, *dir;
	char *defargv[] = { "/bin/sh", 0 };
	uid_t uid;
	gid_t gid;
	int fd;

	argv0 = *argv;
	nsfile = 0;

	while ((opt = getopt(argc, argv, "+cbno")) != -1)
		switch (opt) {
		case 'c': dir = optarg; break;
		case 'b': /* add_bind(optarg); */; break;
		case 'n': nsfile = optarg; break;
		case 'o': /* add_overlay(optarg); */; break;
		default: usage();
		}

	argc -= optind;
	argv += optind;
	if (!argc)
		argv = defargv;

	uid = getuid();
	gid = getgid();

	if (unshare(CLONE_NEWUSER|CLONE_NEWNS) == -1)
		err(1, "unshare");

	if ((fd = open("/proc/self/setgroups", O_RDWR)) != -1) {
		if (write(fd, "deny", 4) == -1)
			err(1, "write /proc/self/setgroups");
		close(fd);
	}

	if (write_map("/proc/self/uid_map", uid, uid))
		err(1, "write /proc/self/uid_map");
	if (write_map("/proc/self/gid_map", gid, gid))
		err(1, "write /proc/self/gid_map");

	if ((dir && chdir(dir) == -1) || chdir("/") == -1)
		err(1, "chdir");


	execvp(*argv, argv);
	err(1, "exec: %s", *argv);
}
