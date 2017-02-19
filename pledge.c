#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "pledge.h"

static char *argv0;
static char promises[256] = "exec stdio";

static void
usage()
{
	fprintf(stderr, "usage: %s [-p promises] command [args]\n", argv0);
	exit(1);
}

static void
addpromises(char *s)
{
	size_t len, pos;
	pos = strlen(promises);
	if (pos)
		promises[pos++] = ' ';
	len = strlen(s);
	if (pos+len >= sizeof promises - 1)
		errx(1, "promises: too long");
	memcpy(promises+pos, s, len);
}

int
main(int argc, char *argv[])
{
	int c;
	argv0 = *argv;
	while((c = getopt(argc, argv, "+dp:v")) != -1)
		switch (c) {
		case 'd': addpromises("debug"); break;
		case 'p': addpromises(optarg); break;
		case 'v': addpromises("verbose"); break;
		default: usage();
		}
	argc -= optind;
	argv += optind;
	if (!argc)
		usage();

	if (pledge(promises, 0) != 0)
		err(1, "%s", promises);

	execvp(*argv, argv);
	err(1, "exec: %s", *argv);
}
