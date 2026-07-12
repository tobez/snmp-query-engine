/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2026, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
/* ABOUTME: Exercises the client_requests_info lifecycle: a cri carrying
 * ABOUTME: SNMPv3 settings is created and torn down; t/cri.t leak-checks it. */
#include "sqe.h"
#include "tap.h"

int
main(void)
{
	struct socket_info sock;
	struct in_addr ip;
	struct client_requests_info *cri;

	bzero(&sock, sizeof sock);
	sock.fd = 7;
	TAILQ_INIT(&sock.send_bufs);

	if (!inet_aton("127.0.0.1", &ip))
		croak(2, "inet_aton");

	cri = get_client_requests_info(&ip, 161, &sock);
	ok(cri != NULL, "get_client_requests_info creates a cri");

	/* what a v3 setopt does (request_setopt.c) */
	cri->v3 = malloc(sizeof(struct snmpv3info));
	if (!cri->v3)
		croak(2, "malloc(v3)");
	bzero(cri->v3, sizeof(struct snmpv3info));

	ok(free_client_request_info(cri) == 1, "free_client_request_info succeeds");

	return tap_done();
}
