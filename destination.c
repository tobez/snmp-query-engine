/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

JudyL by_ip;

struct destination *get_destination(struct in_addr *ip, unsigned port)
{
	void **ip_slot;
	struct destination **dest_slot, *d;

	JLI(ip_slot, by_ip, ip->s_addr);
	if (ip_slot == PJERR)
		croak(2, "get_destination: JLI failed");
	JLI(dest_slot, *ip_slot, port);
	if (dest_slot == PJERR)
		croak(2, "get_destination: JLI failed");
	if (!*dest_slot) {
		d = malloc(sizeof(*d));
		if (!d)
			croak(2, "get_destination: malloc(destination)");
		bzero(d, sizeof(*d));
		d->ip                      = *ip;
		d->port                    = port;
		d->version                 = 1; /* 2c is the default */
		strcpy(d->community, "public");
		d->dest_addr.sin_family    = PF_INET;
		d->dest_addr.sin_addr      = *ip;
		d->dest_addr.sin_port      = htons(port);
		d->max_packets_on_the_wire = DEFAULT_MAX_PACKETS_ON_THE_WIRE;
		d->max_request_packet_size = DEFAULT_MAX_REQUEST_PACKET_SIZE;
		d->timeout                 = DEFAULT_TIMEOUT;
		d->retries                 = DEFAULT_RETRIES;
		d->min_interval            = DEFAULT_MIN_INTERVAL;
		d->max_repetitions         = DEFAULT_MAX_REPETITIONS;
		*dest_slot = d;
	}
	return *dest_slot;
}

struct destination *find_destination(struct in_addr *ip, unsigned port)
{
	void **ip_slot;
	struct destination **dest_slot;

	JLG(ip_slot, by_ip, ip->s_addr);
	if (ip_slot == PJERR || !ip_slot) return NULL;

	JLG(dest_slot, *ip_slot, port);
	if (dest_slot == PJERR || !dest_slot) return NULL;
	return *dest_slot;
}

void
maybe_query_destination(struct destination *dest)
{
	struct client_requests_info **cri_slot;
	Word_t fd;
	struct timeval now;

	if (dest->packets_on_the_wire >= dest->max_packets_on_the_wire) {
		PS.destination_throttles++;
//fprintf(stderr, "%s: max_packets_on_the_wire(%d)\n", inet_ntoa(dest->ip), dest->packets_on_the_wire);
		return;
	}
	if (dest->can_query_at.tv_sec) {
		gettimeofday(&now, NULL);
		if (now.tv_sec < dest->can_query_at.tv_sec ||
			(now.tv_sec == dest->can_query_at.tv_sec && now.tv_usec < dest->can_query_at.tv_usec))
		{
//fprintf(stderr, "%s: min_interval\n", inet_ntoa(dest->ip));
			return;
		}
	}

//fprintf(stderr, "%s: ok(%d)\n", inet_ntoa(dest->ip), dest->packets_on_the_wire);
	/* Then find a client_requests_info, in a round-robin fashion,
	 * which has anything to send.   Be careful with when to stop.
	 */
	fd = dest->fd_of_last_query;
//again:
	JLN(cri_slot, dest->client_requests_info, fd);
	if (dest->fd_of_last_query == 0)
		dest->fd_of_last_query = fd;
	if (!cri_slot) {
		fd = 0;
		JLF(cri_slot, dest->client_requests_info, fd);
		if (!cri_slot) return;  /* no clients for this destination */
	}
	build_snmp_query(*cri_slot);
	// else if (fd != dest->fd_of_last_query)
	//	goto again;
	dest->fd_of_last_query = fd;
	// XXX goto
}

void
destination_timer(struct destination *dest)
{
	// XXX implement me
//fprintf(stderr, "%s: min_interval timer tick (%d)\n", inet_ntoa(dest->ip), dest->packets_on_the_wire);
	destination_stop_timing(dest);
	maybe_query_destination(dest);
}

void
destination_stop_timing(struct destination *dest)
{
	struct timer *t;

	t = find_timer(&dest->can_query_at);
	if (t) TAILQ_REMOVE(&t->throttled_destinations, dest, timer_chain);
	bzero(&dest->can_query_at, sizeof(dest->can_query_at));
}

void
destination_start_timing(struct destination *dest)
{
	struct timer *t;

	destination_stop_timing(dest);
	set_timeout(&dest->can_query_at, dest->min_interval);
	t = new_timer(&dest->can_query_at);
	TAILQ_INSERT_TAIL(&t->throttled_destinations, dest, timer_chain);
}

static void
dump_destination(msgpack_packer *pk, struct destination *dest)
{
	char buf[512];
	Word_t n_cri, n_sid, fd;
	struct client_requests_info **cri_slot;

	#define PACK msgpack_pack_string(pk, buf)
	#define DUMPi(field) msgpack_pack_named_int(pk, #field, dest->field)
	#define DUMPs(field) msgpack_pack_named_string(pk, #field, dest->field)
	snprintf(buf, 512, "DEST(%s:%d)", inet_ntoa(dest->ip), dest->port); PACK;
	msgpack_pack_map(pk, 13);
	DUMPi(version);
	DUMPs(community);
	DUMPi(max_packets_on_the_wire);
	DUMPi(max_request_packet_size);
	DUMPi(timeout);
	DUMPi(retries);
	DUMPi(min_interval);
	DUMPi(max_repetitions);
	DUMPi(packets_on_the_wire);
	/* XXX can_query_at */
	DUMPi(fd_of_last_query);
	JLC(n_cri, dest->client_requests_info, 0, -1);
	msgpack_pack_named_int(pk, "#CRI", n_cri);
	JLC(n_sid, dest->sid_info, 0, -1);
	msgpack_pack_named_int(pk, "#SID", n_sid);

	msgpack_pack_string(pk, "@CRI");
	msgpack_pack_map(pk, n_cri);
	fd = 0;
	JLF(cri_slot, dest->client_requests_info, fd);
	while (cri_slot) {
		dump_client_request_info(pk, *cri_slot);
		JLN(cri_slot, dest->client_requests_info, fd);
	}

	#undef DUMPi
	#undef DUMPs
	#undef PACK
}

void
unclog_all_destinations(void)
{
	struct destination **dest_slot;
	void **ip_slot;
	Word_t ip, port;

	ip = 0;
	JLF(ip_slot, by_ip, ip);
	while (ip_slot) {
		port = 0;
		JLF(dest_slot, *ip_slot, port);
		while (dest_slot) {
			maybe_query_destination(*dest_slot);
			JLN(dest_slot, *ip_slot, port);
		}
		JLN(ip_slot, by_ip, ip);
	}
}

void
dump_all_destinations(msgpack_packer *pk)
{
	struct destination **dest_slot;
	void **ip_slot;
	Word_t ip, port, rc;
	int n_dest = 0;

	ip = 0;
	JLF(ip_slot, by_ip, ip);
	while (ip_slot) {
		JLC(rc, *ip_slot, 0, -1);
		n_dest += rc;
		JLN(ip_slot, by_ip, ip);
	}
	msgpack_pack_map(pk, n_dest);

	ip = 0;
	JLF(ip_slot, by_ip, ip);
	while (ip_slot) {
		port = 0;
		JLF(dest_slot, *ip_slot, port);
		while (dest_slot) {
			dump_destination(pk, *dest_slot);
			JLN(dest_slot, *ip_slot, port);
		}
		JLN(ip_slot, by_ip, ip);
	}
}

