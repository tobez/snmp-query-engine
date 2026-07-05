/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2013, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

static void
do_accept(struct socket_info *lsi)
{
	struct sockaddr_in addr;
	int fd;
	unsigned len;

	len = sizeof(addr);
	if ( (fd = accept(lsi->fd, (struct sockaddr *)&addr, &len)) < 0)
		croak(1, "do_accept: accept");
	log_info("incoming connection", "peer", inet_ntoa(addr.sin_addr), NULL);
	new_client_connection(fd);
}

struct socket_info *listener_si;

void
create_listening_socket(struct in_addr addr, int port)
{
	int fd, on;
	struct sockaddr_in servaddr;
	struct socket_info *si;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		croak(1, "create_listening_socket: socket");

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = PF_INET;
	servaddr.sin_addr        = addr;
	servaddr.sin_port        = htons(port);

	on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
		croak(1, "create_listening_socket: setsockopt of SO_REUSEADDR error");

	if (bind(fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
		croak(1, "create_listening_socket: bind");

	if (listen(fd, 1024) < 0)
		croak(1, "create_listening_socket: listen");

	si = new_socket_info(fd);
	on_read(si, do_accept);
	listener_si = si;
}

