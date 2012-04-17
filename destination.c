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
		d->ip = *ip;
		d->port = port;
		d->max_packets_on_the_wire = DEFAULT_MAX_PACKETS_ON_THE_WIRE;
		d->max_request_packet_size = DEFAULT_MAX_REQUEST_PACKET_SIZE;
		*dest_slot = d;
	}
	return *dest_slot;
}

void
maybe_query_destination(struct destination *dest)
{
	struct client_requests_info **cri_slot, *cri;
	struct oid_info *oi, *oi_temp;
	Word_t fd;
	struct packet_info pi;
	struct encode packet;
	unsigned sid = 0;
	struct cid_info *ci;

	/* XXX first check whether anything can be sent */

	/* Then find a client_requests_info, in a round-robin fashion,
	 * which has anything to send.   Be careful with when to stop.
	 */
	fd = dest->fd_of_last_query;
	JLN(cri_slot, dest->client_requests_info, fd);
	if (!cri_slot) {
		fd = 0;
		JLF(cri_slot, dest->client_requests_info, fd);
		if (!cri_slot) return;  /* no clients for this destination */
	}
	cri = *cri_slot;
	TAILQ_FOREACH_SAFE(oi, &cri->oids_to_query, oid_list, oi_temp) {
		if (!sid) {
			sid = next_sid();
			if (start_snmp_get_packet(&pi, dest->version, dest->community, sid) < 0)
				croak(2, "maybe_query_destination: start_snmp_get_packet");
		}
		if (pi.e.len + oi->oid.len >= dest->max_request_packet_size)
			break;
		if (add_encoded_oid_to_snmp_packet(&pi, &oi->oid) < 0)
			croak(2, "maybe_query_destination: add_encoded_oid_to_snmp_packet");
		TAILQ_REMOVE(&cri->oids_to_query, oi, oid_list);
		ci = get_cid_info(cri, oi->cid);
		if (!ci || ci->n_oids == 0)
			croakx(2, "maybe_query_destination: cid_info unexpectedly missing");
		TAILQ_INSERT_TAIL(&ci->oids_being_queried, oi, oid_list);
		// XXX insert oid into dest->sid_info
{
char buf[4096];
if (!decode_string_oid(oi->oid.buf, oi->oid.len, buf, 4096))
	strcpy(buf, "buf-too-short");
fprintf(stderr, "%d-%u will query as sid %u oid %s\n", oi->fd, oi->cid, sid, buf);
}
	}
	dest->fd_of_last_query = fd;
	if (sid) {
		if (finalize_snmp_packet(&pi, &packet) < 0)
			croak(2, "maybe_query_destination: finalize_snmp_packet");
		fprintf(stderr, "see packet:\n");
		encode_dump(stderr, &packet);
	}
	// XXX goto
}

