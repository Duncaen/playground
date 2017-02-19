#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "pledge.h"

static char *argv0;

static void
usage()
{
	fprintf(stderr, "usage: %s [-p promises] command [args]\n", argv0);
	exit(1);
}

int
main(int argc, char *argv[])
{
	char promises[128];
	char *p, *n;
	ssize_t len;
	int c;

	len = sizeof promises - 1;
	argv0 = *argv;

	memset(promises, 0, sizeof promises);
	strcpy(promises, "exec stdio");
	p = promises+strlen(promises);

	while((c = getopt(argc, argv, "+p:")) != -1)
		switch (c) {
		case 'p':
			n = p+strlen(optarg)+1;
			if (n-promises >= len)
				errx(1, "promises: too long");
			*p++ = ' ';
			memcpy(p, optarg, n-p);
			p = n;
			break;
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
