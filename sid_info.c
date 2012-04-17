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
}
