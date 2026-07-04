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
	fprintf(f, "\t-d\t\tdebug logging\n");
	fprintf(f, "\t-h\t\tproduce usage text and quit\n");
	fprintf(f, "\t-p port\t\tlisten on port prt instead of default 7667\n");
	fprintf(f, "\t-q\t\tquiet operation (warnings and errors only)\n");
	fprintf(f, "\t-v\t\tprint program version and quit\n");
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
	PS.program_version = 2023082200; /* frozen for protocol compatibility; see SQE_VERSION */

	while ( (o = getopt(argc, argv, "dhp:qv")) != -1) {
		switch (o) {
		case 'd':
			opt_log_level = LL_DEBUG;
			break;
		case 'h':
			usage(NULL);
			break;
		case 'p':
			port = strtol(optarg, NULL, 10);
			break;
		case 'q':
			opt_log_level = LL_WARN;
			break;
		case 'v':
			printf("snmp-query-engine %s\n", SQE_VERSION);
			exit(0);
		default:
			usage("");
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage("extraneous arguments");

	log_setup();
	log_debug("debug logging enabled");

    if (populate_well_known_oids() < 0) {
        log_error("unable to populate well-known oids: %s", strerror(errno));
        exit(1);
    }

	create_snmp_socket();
	create_listening_socket(port);
	event_loop();

	return 0;
}

