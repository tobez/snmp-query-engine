#include "sqe.h"

struct sid_info *new_sid_info(struct client_requests_info *cri)
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
	TAILQ_INIT(&si->oids_being_queried);
	if (start_snmp_get_packet(&si->pb, dest->version, dest->community, sid) < 0)
		croak(2, "new_sid_info: start_snmp_get_packet");
	*si_slot = si;
	TAILQ_INSERT_TAIL(&cri->sid_infos, si, sid_list);
	return si;
}

void
build_snmp_query(struct client_requests_info *cri)
{
	struct oid_info *oi, *oi_temp;
	struct sid_info *si = NULL;
	struct destination *dest;
	struct cid_info *ci;

	if (TAILQ_EMPTY(&cri->oids_to_query))	return;

	dest = cri->dest;
	si = new_sid_info(cri);

	TAILQ_FOREACH_SAFE(oi, &cri->oids_to_query, oid_list, oi_temp) {
		if (si->pb.e.len + oi->oid.len >= dest->max_request_packet_size)
			break;
		if (add_encoded_oid_to_snmp_packet(&si->pb, &oi->oid) < 0)
			croak(2, "build_snmp_query: add_encoded_oid_to_snmp_packet");
		TAILQ_REMOVE(&cri->oids_to_query, oi, oid_list);
		ci = get_cid_info(cri, oi->cid);
		if (!ci || ci->n_oids == 0)
			croakx(2, "build_snmp_query: cid_info unexpectedly missing");
		ci->n_oids_being_queried++;
		TAILQ_INSERT_TAIL(&si->oids_being_queried, oi, oid_list);
	}
	if (finalize_snmp_packet(&si->pb, &si->packet) < 0)
		croak(2, "build_snmp_query: finalize_snmp_packet");
	fprintf(stderr, "see packet:\n");
	encode_dump(stderr, &si->packet);
	snmp_send(dest, &si->packet);
}

static void *by_time = NULL;

void
sid_start_timing(struct sid_info *si)
{
	void **sec_slot;
	struct sid_info_head **usec_slot, *list;

	gettimeofday(&si->will_timeout_at, NULL);
	JLI(sec_slot, by_time, si->will_timeout_at.tv_sec);
	if (sec_slot == PJERR)
		croak(2, "sid_start_timing: JLI(by_time) failed");
	JLI(usec_slot, *sec_slot, si->will_timeout_at.tv_usec);
	if (usec_slot == PJERR)
		croak(2, "sid_start_timing: JLI(*sec_slot) failed");
	if (!*usec_slot) {
		list = malloc(sizeof(*list));
		if (!list)
			croak(2, "sid_start_timing: malloc(sid_info_head)");
		TAILQ_INIT(list);
		*usec_slot = list;
	}
	list = *usec_slot;
	TAILQ_INSERT_TAIL(list, si, same_timeout);
}

void
sid_stop_timing(struct sid_info *si)
{
}
