/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

static JudyL dest_by_fd;  // -> JudyL(by ip) -> JudyL(by port) -> destination

struct client_requests_info *
get_client_requests_info(struct in_addr *ip, unsigned port, struct socket_info *si)
{
	struct destination *dest;
	void **fd_slot, **ip_slot;
	struct client_requests_info **cri_slot, **dest_cri_slot, *cri;

	dest = get_destination(ip, port);

	JLI(fd_slot, dest_by_fd, si->fd);
	if (fd_slot == PJERR)
		croak(2, "get_client_requests_info: JLI(fd) failed");
	JLI(ip_slot, *fd_slot, ip->s_addr);
	if (ip_slot == PJERR)
		croak(2, "get_client_requests_info: JLI(ip) failed");
	JLI(cri_slot, *ip_slot, port);
	if (cri_slot == PJERR)
		croak(2, "get_client_requests_info: JLI(port) failed");
	if (!*cri_slot) {
		cri = malloc(sizeof(*cri));
		if (!cri)
			croak(2, "get_client_requests_info: malloc(cri)");

		PS.active_cr_infos++;
		PS.total_cr_infos++;
		si->PS.active_cr_infos++;
		si->PS.total_cr_infos++;

		bzero(cri, sizeof(*cri));
		cri->dest = dest;
		cri->fd   = si->fd;
		cri->si   = si;
		TAILQ_INIT(&cri->oids_to_query);
		TAILQ_INIT(&cri->sid_infos);
		*cri_slot = cri;
	}

	JLI(dest_cri_slot, dest->client_requests_info, si->fd);
	if (dest_cri_slot == PJERR)
		croak(2, "get_client_requests_info: JLI(dest/fd) failed");
	*dest_cri_slot = *cri_slot;
	return *cri_slot;
}

int
free_all_client_request_info_for_fd(int fd)
{
	void **fd_slot, **ip_slot;
	struct client_requests_info **cri_slot;
	Word_t ip, port;
	Word_t rc;

	JLG(fd_slot, dest_by_fd, fd);
	if (fd_slot == PJERR)
		croak(2, "free_all_client_request_info_for_fd: JLG(fd) failed");
	if (!fd_slot)
		return 1;

	ip = 0;
	JLF(ip_slot, *fd_slot, ip);
	while (ip_slot) {
		port = 0;
		JLF(cri_slot, *ip_slot, port);
		while (cri_slot) {
			free_client_request_info(*cri_slot);
			JLN(cri_slot, *ip_slot, port);
		}
		JLFA(rc, *ip_slot);
		JLN(ip_slot, *fd_slot, ip);
	}
	JLFA(rc, *fd_slot);
	JLD(rc, dest_by_fd, fd);
	return 1;
}

int
free_client_request_info(struct client_requests_info *cri)
{
	struct cid_info **ci_slot;
	Word_t cid;
	Word_t rc;
	struct sid_info *si, *si_temp;

	PS.active_cr_infos--;
	cri->si->PS.active_cr_infos--;
	si = TAILQ_FIRST(&cri->sid_infos);
	while (si != NULL) {
		si_temp = TAILQ_NEXT(si, sid_list);
		free_sid_info(si);
		si = si_temp;
	}
	TAILQ_INIT(&cri->sid_infos);

	free_oid_info_list(&cri->oids_to_query);
	cid = 0;
	JLF(ci_slot, cri->cid_info, cid);
	while (ci_slot) {
		free_cid_info(*ci_slot);
		JLN(ci_slot, cri->cid_info, cid);
	}
	JLFA(rc, cri->cid_info);
	JLD(rc, cri->dest->client_requests_info, cri->fd);
	free(cri);
	return 1;
}

void
dump_client_request_info(msgpack_packer *pk, struct client_requests_info *cri)
{
	char buf[512];
	Word_t n_cid, n_query_queue, n_sid, cid;
	struct oid_info *oi;
	struct sid_info *si;
	struct cid_info **cid_slot;

	#define PACK msgpack_pack_string(pk, buf)
	#define DUMPi(field) msgpack_pack_named_int(pk, #field, cri->field)
	#define DUMPs(field) msgpack_pack_named_string(pk, #field, cri->field)
	snprintf(buf, 512, "CRI(%d)", cri->fd); PACK;
	msgpack_pack_map(pk, 6);

	msgpack_pack_string(pk, "dest");
	snprintf(buf, 512, "DEST(%s:%d)", inet_ntoa(cri->dest->ip), cri->dest->port); PACK;

	DUMPi(fd);

	JLC(n_cid, cri->cid_info, 0, -1);
	msgpack_pack_named_int(pk, "#CID", n_cid);

	n_query_queue = 0;
	TAILQ_FOREACH(oi, &cri->oids_to_query, oid_list) {
		n_query_queue++;
	}
	msgpack_pack_named_int(pk, "#QUERY_QUEUE", n_query_queue);

	n_sid = 0;
	TAILQ_FOREACH(si, &cri->sid_infos, sid_list) {
		n_sid++;
	}
	msgpack_pack_named_int(pk, "#SID", n_sid);

	msgpack_pack_string(pk, "@CID");
	msgpack_pack_map(pk, n_cid);
	cid = 0;
	JLF(cid_slot, cri->cid_info, cid);
	while (cid_slot) {
		dump_cid_info(pk, *cid_slot);
		JLN(cid_slot, cri->cid_info, cid);
	}

	#undef DUMPi
	#undef DUMPs
	#undef PACK
}
