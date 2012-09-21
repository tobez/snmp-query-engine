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
		d->dest_addr.sin_family    = PF_INET;
		d->dest_addr.sin_addr      = *ip;
		d->dest_addr.sin_port      = htons(port);
		d->max_packets_on_the_wire = DEFAULT_MAX_PACKETS_ON_THE_WIRE;
		d->max_request_packet_size = DEFAULT_MAX_REQUEST_PACKET_SIZE;
		d->max_reply_packet_size   = DEFAULT_MAX_REPLY_PACKET_SIZE;
		d->estimated_value_size    = DEFAULT_ESTIMATED_VALUE_SIZE;
		d->max_oids_per_request    = DEFAULT_MAX_OIDS_PER_REQUEST;
		d->min_interval            = DEFAULT_MIN_INTERVAL;
		d->max_repetitions         = DEFAULT_MAX_REPETITIONS;
		d->ignore_threshold        = DEFAULT_IGNORE_THRESHOLD;
		d->ignore_duration         = DEFAULT_IGNORE_DURATION;
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
flush_ignored_destination(struct destination *dest)
{
	struct client_requests_info *cri;
	Word_t fd;
	struct client_requests_info **cri_slot;
	struct sid_info *si, *si_temp;
	struct oid_info *oi, *oi_temp;
	struct cid_info *ci;

	fd = 0;
	JLF(cri_slot, dest->client_requests_info, fd);
	while (cri_slot) {
		cri = *cri_slot;

		si = TAILQ_FIRST(&cri->sid_infos);
		while (si != NULL) {
			si_temp = TAILQ_NEXT(si, sid_list);
			if (si->table_oid) {
				oid_done(si, si->table_oid, &BER_IGNORED, RT_GETTABLE);
				si->table_oid = NULL;
			} else {
				all_oids_done(si, &BER_IGNORED);
			}
			free_sid_info(si);
			si = si_temp;
		}
		TAILQ_INIT(&cri->sid_infos);

		TAILQ_FOREACH_SAFE(oi, &cri->oids_to_query, oid_list, oi_temp) {
			ci = get_cid_info(cri, oi->cid);
			if (!ci || ci->n_oids == 0)
				croakx(2, "flush_ignored_destination: cid_info unexpectedly missing");
			/* XXX free old value? */
			oi->value = ber_rewind(ber_dup(&BER_IGNORED));
			oi->sid = 0;
			TAILQ_REMOVE(&cri->oids_to_query, oi, oid_list);
			TAILQ_INSERT_TAIL(&ci->oids_done, oi, oid_list);
			PS.oids_ignored++;
			ci->n_oids_done++;
			if (ci->n_oids_done == ci->n_oids)
				cid_reply(ci, oi->last_known_table_entry ? RT_GETTABLE : RT_GET);
		}

		JLN(cri_slot, dest->client_requests_info, fd);
	}
	dest->packets_on_the_wire = 0;
}

void
maybe_query_destination(struct destination *dest)
{
	struct client_requests_info **cri_slot;
	Word_t fd;
	struct timeval now;

	if (dest->ignore_threshold && dest->timeouts_in_a_row >= dest->ignore_threshold) {
		PS.destination_ignores++;
		dest->timeouts_in_a_row = 0;
		set_timeout(&dest->ignore_until, dest->ignore_duration);
	}
	if (dest->ignore_until.tv_sec > 0) {
		gettimeofday(&now, NULL);
		if (now.tv_sec < dest->ignore_until.tv_sec ||
			(now.tv_sec == dest->ignore_until.tv_sec && now.tv_usec < dest->ignore_until.tv_usec))
		{
			flush_ignored_destination(dest);
			return;
		} else {
			/* we are past ignore duration here */
			bzero(&dest->ignore_until, sizeof(dest->ignore_until));
		}
	}

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
	msgpack_pack_map(pk, 14);
	DUMPi(max_packets_on_the_wire);
	DUMPi(max_request_packet_size);
	DUMPi(max_reply_packet_size);
	DUMPi(estimated_value_size);
	DUMPi(max_oids_per_request);
	DUMPi(min_interval);
	DUMPi(max_repetitions);
	DUMPi(ignore_threshold);
	DUMPi(ignore_duration);
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

