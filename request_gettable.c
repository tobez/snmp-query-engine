#include "sqe.h"

/*
 * gettable request:
 * [ 0, $cid, $ip, $port, $oid ]
 *
 */

int
handle_gettable_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	unsigned port = 65536;
	struct in_addr ip;
	struct client_requests_info *cri;
	struct cid_info *ci;
	struct oid_info *oi;

	if (o->via.array.size != 5)
		return error_reply(si, RT_GETTABLE|RT_ERROR, cid, "bad request length");

	if (o->via.array.ptr[RI_GETTABLE_PORT].type == MSGPACK_OBJECT_POSITIVE_INTEGER)
		port = o->via.array.ptr[RI_GETTABLE_PORT].via.u64;
	if (port > 65535)
		return error_reply(si, RT_GETTABLE|RT_ERROR, cid, "bad port number");

	if (!object2ip(&o->via.array.ptr[RI_GETTABLE_IP], &ip))
		return error_reply(si, RT_GETTABLE|RT_ERROR, cid, "bad IP");

	cri = get_client_requests_info(&ip, port, si->fd);
	cri->si = si;
	ci = get_cid_info(cri, cid);
	if (ci->n_oids != 0)
		return error_reply(si, RT_GETTABLE|RT_ERROR, cid, "duplicate request id");

	if (!( oi = allocate_oid_info(&o->via.array.ptr[RI_GETTABLE_OID], ci)))
		return error_reply(si, RT_GETTABLE|RT_ERROR, cid, "bad oid");
	oi->last_known_table_entry = oi;
	ci->n_oids++;

	TAILQ_INSERT_TAIL(&cri->oids_to_query, oi, oid_list);
	maybe_query_destination(cri->dest);
	return 0;
}