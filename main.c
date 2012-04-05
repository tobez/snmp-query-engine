#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "sqe.h"

#if defined(__linux__)
static char proggy[MAXPATHLEN];
#endif

const char *thisprogname(void)
{
#if defined(__FreeBSD__)
	return getprogname();
#elif defined(__APPLE__)
	return getprogname();
#elif defined(__sun__)
	return getexecname();
#elif defined(__linux__)
	if (readlink("/proc/self/exe", proggy, MAXPATHLEN) != -1)
		return proggy;
	return "";
#else
#error "unsupported OS"
#endif
}

void
usage(char *err)
{
	FILE *f = err ? stderr : stdout;
	if (err && *err)
		fprintf(f, "%s\n", err);
	fprintf(f, "Usage:\n");
	fprintf(f, "    %s [options]\n", thisprogname());
	fprintf(f, "Usage parameters:\n");
	fprintf(f, "\t-h\t\tproduce usage text and quit\n");
	fprintf(f, "\t-p prt\tlisten on port prt instead of default 7667\n");
	exit(err ? 1 : 0);
}

int listen_sock;

void
create_listening_socket(int port)
{
}

int
main(int argc, char **argv)
{
	int o;
	int port = 7667;

	while ( (o = getopt(argc, argv, "hp:")) != -1) {
		switch (o) {
		case 'h':
			usage(NULL);
			break;
		case 'p':
			port = strtol(optarg, NULL, 10);
			break;
		default:
			usage("");
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage("extraneous arguments");

	create_listening_socket(port);
	event_loop();

	return 0;
}

