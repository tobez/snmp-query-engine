/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2014, Anton Berezin <tobez@tobez.org>
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
	fprintf(f, "\t-p port\t\tlisten on port prt instead of default 7667\n");
	if (0) {
		fprintf(f, "\t-f\t\tstay in foreground\n");
		fprintf(f, "\t-p pidfile\tstore process ID in pidfile\n\t\t\t(default: do not store process ID)\n");
		fprintf(f, "\t-l logfile\tprint statistics and verbose output\n\t\t\tinto logfile (default: use stdout)\n");
		fprintf(f, "\t\t\tSend HUP signal to reopen the logfile\n");
	}
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
	PS.max_packets_on_the_wire = 1000000;
	PS.program_version = 2014052300;

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

    if (populate_well_known_oids() < 0) {
        fprintf(stderr, "unable to populate well-known oids: %s\n", strerror(errno));
        exit(1);
    }

	create_snmp_socket();
	create_listening_socket(port);
	event_loop();

	return 0;
}

