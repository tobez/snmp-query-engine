/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

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
	fprintf(f, "\t-q\t\tquiet operation\n");
	exit(err ? 1 : 0);
}

int
main(int argc, char **argv)
{
	int o;
	int port = 7667;

	gettimeofday(&prog_start, NULL);
	bzero(&PS, sizeof(PS));

	while ( (o = getopt(argc, argv, "hp:q")) != -1) {
		switch (o) {
		case 'h':
			usage(NULL);
			break;
		case 'p':
			port = strtol(optarg, NULL, 10);
			break;
		case 'q':
			opt_quiet = 1;
			break;
		default:
			usage("");
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage("extraneous arguments");

	create_snmp_socket();
	create_listening_socket(port);
	event_loop();

	return 0;
}

