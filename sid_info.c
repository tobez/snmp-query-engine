/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

struct sid_info *
new_sid_info(struct client_requests_info *cri)
{
	struct sid_info *si, **si_slot;
	unsigned sid;
	struct destination *dest;

	sid = next_sid();
	dest = cri->dest;
	JLI(si_slot, dest->sid_info, sid);
	if (si_slot == PJERR)
		croak(2, "new_sid_info: JLI(sid_info) failed");
	if (*si_slot)
		croak(2, "new_sid_info: sid_info must not be there");
	si = malloc(sizeof(*si));
	if (!si)
		croak(2, "new_sid_info: malloc(sid_info)");

	bzero(si, sizeof(*si));
	si->sid = sid;
	si->cri = cri;
	si->retries_left = dest->retries;
	si->version = dest->version;
	TAILQ_INIT(&si->oids_being_queried);
	if (start_snmp_packet(&si->pb, si->version, dest->community, sid) < 0)
		croak(2, "new_sid_info: start_snmp_get_packet");
	*si_slot = si;
	TAILQ_INSERT_TAIL(&cri->sid_infos, si, sid_list);

	PS.active_sid_infos++;
	PS.total_sid_infos++;
	cri->si->PS.active_sid_infos++;
	cri->si->PS.total_sid_infos++;
	return si;
}

struct sid_info *
find_sid_info(struct destination *dest, unsigned sid)
{
	struct sid_info **si_slot;

	JLG(si_slot, dest->sid_info, sid);
	if (si_slot == PJERR || !si_slot)	return NULL;
	return *si_slot;
}

void
build_snmp_query(struct client_requests_info *cri)
{
	struct oid_info *oi, *oi_temp;
	struct sid_info *si = NULL;
	struct destination *dest;
	struct cid_info *ci;

	if (TAILQ_EMPTY(&cri->oids_to_query))	return; /* XXX */

	dest = cri->dest;
	si = new_sid_info(cri);

	oi = TAILQ_FIRST(&cri->oids_to_query);
	if (oi->last_known_table_entry) {
		/* GETTABLE */
		if (add_encoded_oid_to_snmp_packet(&si->pb, &oi->last_known_table_entry->oid) < 0)
			croak(2, "build_snmp_query: add_encoded_oid_to_snmp_packet");
		TAILQ_REMOVE(&cri->oids_to_query, oi, oid_list);
		oi->sid = si->sid;
		ci = get_cid_info(cri, oi->cid);
		if (!ci || ci->n_oids == 0)
			croakx(2, "build_snmp_query: cid_info unexpectedly missing for table oid");
		ci->n_oids_being_queried++;

		si->table_oid = oi;
		PS.oids_requested++;
		cri->si->PS.oids_requested++;

		if ( (si->sid_offset_in_a_packet =
			  finalize_snmp_packet(&si->pb, &si->packet,
								   dest->version == 0 ? PDU_GET_NEXT_REQUEST : PDU_GET_BULK_REQUEST,
								   10)) < 0)
			croak(2, "build_snmp_query: finalize_snmp_packet");
	} else {
		TAILQ_FOREACH_SAFE(oi, &cri->oids_to_query, oid_list, oi_temp) {
			if (oi->last_known_table_entry) continue; /* Skip GETTABLE requests */
			if (si->pb.e.len + oi->oid.len >= dest->max_request_packet_size)
				break;
			PS.oids_requested++;
			cri->si->PS.oids_requested++;
			if (add_encoded_oid_to_snmp_packet(&si->pb, &oi->oid) < 0)
				croak(2, "build_snmp_query: add_encoded_oid_to_snmp_packet");
			TAILQ_REMOVE(&cri->oids_to_query, oi, oid_list);
			oi->sid = si->sid;
			ci = get_cid_info(cri, oi->cid);
			if (!ci || ci->n_oids == 0)
				croakx(2, "build_snmp_query: cid_info unexpectedly missing");
			ci->n_oids_being_queried++;
			TAILQ_INSERT_TAIL(&si->oids_being_queried, oi, oid_list);
		}
		if ( (si->sid_offset_in_a_packet = finalize_snmp_packet(&si->pb, &si->packet, PDU_GET_REQUEST, 0)) < 0)
			croak(2, "build_snmp_query: finalize_snmp_packet");
	}
	sid_start_timing(si);
	si->retries_left--;

	PS.snmp_sends++;
	si->cri->si->PS.snmp_sends++;
	if (si->version == 0) {
		PS.snmp_v1_sends++;
		si->cri->si->PS.snmp_v1_sends++;
	} else {
		PS.snmp_v2c_sends++;
		si->cri->si->PS.snmp_v2c_sends++;
	}
	snmp_send(dest, &si->packet);
}

void
sid_start_timing(struct sid_info *si)
{
	struct timer *t;

	set_timeout(&si->will_timeout_at, si->cri->dest->timeout);
	t = new_timer(&si->will_timeout_at);
	TAILQ_INSERT_TAIL(&t->timed_out_sids, si, timer_chain);
}

void
sid_stop_timing(struct sid_info *si)
{
	struct timer *t;

	t = find_timer(&si->will_timeout_at);
	if (t) TAILQ_REMOVE(&t->timed_out_sids, si, timer_chain);
	bzero(&si->will_timeout_at, sizeof(si->will_timeout_at));
}

void
free_sid_info(struct sid_info *si)
{
	Word_t rc;
	/* The equivalent of
	 * TAILQ_REMOVE(&si->cri->sid_infos, si, sid_list);
	 * should be done by the caller.
	 * Reason: free_client_request_info() does it more
	 * efficiently and thus does not need to TAILQ_REMOVE.
	 */
	PS.active_sid_infos--;
	si->cri->si->PS.active_sid_infos--;

	TAILQ_REMOVE(&si->cri->sid_infos, si, sid_list);
	JLD(rc, si->cri->dest->sid_info, si->sid);
	sid_stop_timing(si);
	free(si->packet.buf);
	free_oid_info_list(&si->oids_being_queried);
	if (si->table_oid)
		free_oid_info(si->table_oid);
	free(si);
}

void resend_query_with_new_sid(struct sid_info *si)
{
	struct sid_info **si_slot;
	struct oid_info *oi;
	Word_t rc;

	JLD(rc, si->cri->dest->sid_info, si->sid);
	si->sid = next_sid();
	si->packet.buf[si->sid_offset_in_a_packet+0] = (si->sid >> 24) & 0xff;
	si->packet.buf[si->sid_offset_in_a_packet+1] = (si->sid >> 16) & 0xff;
	si->packet.buf[si->sid_offset_in_a_packet+2] = (si->sid >> 8) & 0xff;
	si->packet.buf[si->sid_offset_in_a_packet+3] = si->sid & 0xff;

	TAILQ_FOREACH(oi, &si->oids_being_queried, oid_list) {
		oi->sid = si->sid;
	}

	JLI(si_slot, si->cri->dest->sid_info, si->sid);
	if (si_slot == PJERR)
		croak(2, "resend_query_with_new_sid: JLI(sid_info) failed");
	if (*si_slot)
		croak(2, "resend_query_with_new_sid: sid_info must not be there");
	*si_slot = si;

	sid_start_timing(si);
	si->retries_left--;

	PS.snmp_sends++;
	si->cri->si->PS.snmp_sends++;
	if (si->version == 0) {
		PS.snmp_v1_sends++;
		si->cri->si->PS.snmp_v1_sends++;
	} else {
		PS.snmp_v2c_sends++;
		si->cri->si->PS.snmp_v2c_sends++;
	}
	PS.snmp_retries++;
	si->cri->si->PS.snmp_retries++;
	snmp_send(si->cri->dest, &si->packet);
}

void
sid_timer(struct sid_info *si)
{
	struct destination *dest;
	PS.udp_timeouts++;
	si->cri->si->PS.udp_timeouts++;
	si->cri->dest->packets_on_the_wire--;
	if (si->cri->dest->packets_on_the_wire < 0)
		si->cri->dest->packets_on_the_wire = 0;
	sid_stop_timing(si);
	if (si->retries_left > 0) {
		resend_query_with_new_sid(si);
		return;
	}
	PS.snmp_timeouts++;
	si->cri->si->PS.snmp_timeouts++;

	if (si->table_oid) {
		oid_done(si, si->table_oid, &BER_TIMEOUT, RT_GETTABLE);
		si->table_oid = NULL;
	} else {
		all_oids_done(si, &BER_TIMEOUT);
	}
	dest = si->cri->dest;
	free_sid_info(si);
	maybe_query_destination(si->cri->dest);
}

void
oid_done(struct sid_info *si, struct oid_info *oi, struct ber *val, int op)
{
	struct client_requests_info *cri;
	struct cid_info *ci;

	cri = si->cri;
	ci = get_cid_info(cri, oi->cid);
	if (!ci || ci->n_oids == 0)
		croakx(2, "oid_done: cid_info unexpectedly missing");
	/* XXX free old value? */
	oi->value = ber_rewind(ber_dup(val));
	oi->sid = 0;
	if (op != RT_GETTABLE)
		TAILQ_REMOVE(&si->oids_being_queried, oi, oid_list);
	TAILQ_INSERT_TAIL(&ci->oids_done, oi, oid_list);
	ci->n_oids_being_queried--;
	ci->n_oids_done++;
	if (ci->n_oids_done == ci->n_oids)
		cid_reply(ci, op);
}

void
got_table_oid(struct sid_info *si, struct oid_info *table_oi, struct ber *oid, struct ber *val)
{
	struct client_requests_info *cri;
	struct cid_info *ci;
	struct oid_info *oi;

	cri = si->cri;
	ci = get_cid_info(cri, table_oi->cid);
	if (!ci || ci->n_oids == 0)
		croakx(2, "got_table_oid: cid_info unexpectedly missing");

	oi = malloc(sizeof(*oi));
	if (!oi)
		croak(2, "got_table_oid: malloc(oid_info)");
	bzero(oi, sizeof(*oi));
	oi->cid = table_oi->cid;
	oi->fd  = ci->fd;
	oi->oid = ber_dup(oid);
	oi->value = ber_rewind(ber_dup(val));
	oi->sid = 0;
	table_oi->last_known_table_entry = oi;

	PS.active_oid_infos++;
	PS.total_oid_infos++;

	TAILQ_INSERT_TAIL(&ci->oids_done, oi, oid_list);
	ci->n_oids_done++;
	ci->n_oids++;
}

void
all_oids_done(struct sid_info *si, struct ber *val)
{
	struct oid_info *oi, *oi_temp;
	/* XXX handle si->table_oid stuff as well */
	TAILQ_FOREACH_SAFE(oi, &si->oids_being_queried, oid_list, oi_temp) {
		oid_done(si, oi, val, RT_GET);
	}
}

void
process_sid_info_response(struct sid_info *si, struct ber *e)
{
	unsigned error_status;
	unsigned error_index;
	char *trace;
	int oids_stop;
	struct ber oid, val;
	struct oid_info *oi;
	int table_done = 0;
	struct cid_info *ci;

	/* SNMP packet must be positioned past request id field */

	#define CHECK(prob, val) if ((val) < 0) { trace = prob; goto bad_snmp_packet; }
	CHECK("decoding error status", decode_integer(e, -1, &error_status));
	CHECK("decoding error index", decode_integer(e, -1, &error_index));
	CHECK("oids sequence", decode_sequence(e, &oids_stop));
	while (inside_sequence(e, oids_stop)) {
		CHECK("bindvar", decode_sequence(e, NULL));
		CHECK("oid", decode_oid(e, &oid));
		CHECK("value", decode_any(e, &val));
		PS.oids_returned_from_snmp++;
		si->cri->si->PS.oids_returned_from_snmp++;
		if (si->table_oid) {
			if (oid_belongs_to_table(&oid, &si->table_oid->oid)) {
				got_table_oid(si, si->table_oid, &oid, &val);
			} else {
				table_done = 1;
			}
		} else {
			TAILQ_FOREACH(oi, &si->oids_being_queried, oid_list) {
				if (ber_equal(&oid, &oi->oid)) {
					oid_done(si, oi, &val, RT_GET);
					break;
				}
			}
		}
	}
	if (si->table_oid) {
		ci = get_cid_info(si->cri, si->table_oid->cid);
		ci->n_oids_being_queried--;
		if (table_done) {
			free_oid_info(si->table_oid);
			si->table_oid = NULL;
			ci->n_oids--;
			if (ci->n_oids_done == ci->n_oids)
				cid_reply(ci, RT_GETTABLE);
		} else {
			TAILQ_INSERT_TAIL(&si->cri->oids_to_query, si->table_oid, oid_list);
			si->table_oid = NULL;
			maybe_query_destination(si->cri->dest);
		}
	} else {
		if (!TAILQ_EMPTY(&si->oids_being_queried)) {
			fprintf(stderr, "SID %u: unexpectedly, not all oids are accounted for!\n", si->sid);
			all_oids_done(si, &BER_MISSING);
		}
	}
	PS.good_snmp_responses++;
	si->cri->si->PS.good_snmp_responses++;
	#undef CHECK

	return;
bad_snmp_packet:
	PS.bad_snmp_responses++;
	fprintf(stderr, "sid %u: bad SNMP packet, ignoring: %s\n", si->sid, trace);
}
