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
	exit(err ? 1 : 0);
}

static void
client_input(struct socket_info *si)
{
	fprintf(stderr, "some data's here\n");
}

static void
do_accept(struct socket_info *lsi)
{
	struct sockaddr_in addr;
	int fd;
	unsigned len;
	struct socket_info *si;

	len = sizeof(addr);
	if ( (fd = accept(lsi->fd, (struct sockaddr *)&addr, &len)) < 0)
		croak(1, "do_accept: accept");
	fprintf(stderr, "incoming connection from %s!\n", inet_ntoa(addr.sin_addr));
	si = new_socket_info(fd);
	on_read(si, client_input);
}

void
create_listening_socket(int port)
{
	int fd;
	struct sockaddr_in servaddr;
	struct socket_info *si;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		croak(1, "create_listening_socket: socket");

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = PF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	servaddr.sin_port        = htons(port);

	if (bind(fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
		croak(1, "create_listening_socket: bind");

	if (listen(fd, 1024) < 0)
		croak(1, "create_listening_socket: listen");

	si = new_socket_info(fd);
	on_read(si, do_accept);
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

