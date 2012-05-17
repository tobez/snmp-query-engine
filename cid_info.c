/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

struct cid_info *
get_cid_info(struct client_requests_info *cri, unsigned cid)
{
	struct cid_info **ci_slot, *ci;

	JLI(ci_slot, cri->cid_info, cid);
	if (ci_slot == PJERR)
		croak(2, "get_cid_info: JLI(cid) failed");
	if (!*ci_slot) {
		ci = malloc(sizeof(*ci));
		if (!ci)
			croak(2, "get_cid_info: malloc(cid_info)");

		PS.active_cid_infos++;
		PS.total_cid_infos++;
		cri->si->PS.active_cid_infos++;
		cri->si->PS.total_cid_infos++;

		bzero(ci, sizeof(*ci));
		ci->cri = cri;
		ci->fd = cri->fd;
		ci->cid = cid;
		TAILQ_INIT(&ci->oids_done);
		*ci_slot = ci;
	}
	return *ci_slot;
}

int
free_cid_info(struct cid_info *ci)
{
	Word_t rc;

	PS.active_cid_infos--;
	ci->cri->si->PS.active_cid_infos--;
	JLD(rc, ci->cri->cid_info, ci->cid);
	free_oid_info_list(&ci->oids_done);
	free(ci);
	return 1;
}

void
cid_reply(struct cid_info *ci, int type)
{
	msgpack_sbuffer* buffer = msgpack_sbuffer_new();
	msgpack_packer* pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	struct oid_info *oi;

	msgpack_pack_array(pk, 3);
	msgpack_pack_int(pk, type|RT_REPLY);
	msgpack_pack_int(pk, ci->cid);
	msgpack_pack_array(pk, ci->n_oids_done);
	TAILQ_FOREACH(oi, &ci->oids_done, oid_list) {
		msgpack_pack_array(pk, 2);
		msgpack_pack_oid(pk, oi->oid);
		msgpack_pack_ber(pk, oi->value);
		PS.oids_returned_to_client++;
		ci->cri->si->PS.oids_returned_to_client++;
	}
	tcp_send(ci->cri->si, buffer->data, buffer->size);
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
	free_cid_info(ci);
}

void
dump_cid_info(msgpack_packer *pk, struct cid_info *ci)
{
	char buf[512];
	Word_t n_oids_done;
	struct oid_info *oi;

	#define PACK msgpack_pack_string(pk, buf)
	#define DUMPi(field) msgpack_pack_named_int(pk, #field, ci->field)
	#define DUMPs(field) msgpack_pack_named_string(pk, #field, ci->field)
	snprintf(buf, 512, "CID(%d)", ci->cid); PACK;
	msgpack_pack_map(pk, 7);

	msgpack_pack_string(pk, "cri");
	snprintf(buf, 512, "CRI(%s:%d->%d)", inet_ntoa(ci->cri->dest->ip), ci->cri->dest->port, ci->cri->fd); PACK;

	DUMPi(cid);
	DUMPi(fd);
	DUMPi(n_oids);
	DUMPi(n_oids_being_queried);
	DUMPi(n_oids_done);

	n_oids_done = 0;
	TAILQ_FOREACH(oi, &ci->oids_done, oid_list) {
		n_oids_done++;
	}
	msgpack_pack_named_int(pk, "#OIDS_DONE", n_oids_done);

	#undef DUMPi
	#undef DUMPs
	#undef PACK
}
