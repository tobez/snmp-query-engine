/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2013, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

/*
 * get request:
 * [ 0, $cid, $ip, $port, [$oids] ]
 *
 */

int
handle_get_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	unsigned port = 65536;
	struct in_addr ip;
	struct client_requests_info *cri;
	struct cid_info *ci;
	struct oid_info_head oi;

	if (o->via.array.size != 5)
		return error_reply(si, RT_GET|RT_ERROR, cid, "bad request length");

	if (o->via.array.ptr[RI_GET_PORT].type == MSGPACK_OBJECT_POSITIVE_INTEGER)
		port = o->via.array.ptr[RI_GET_PORT].via.u64;
	if (port > 65535)
		return error_reply(si, RT_GET|RT_ERROR, cid, "bad port number");

	if (!object2ip(&o->via.array.ptr[RI_GET_IP], &ip))
		return error_reply(si, RT_GET|RT_ERROR, cid, "bad IP");

	if (o->via.array.ptr[RI_GET_OIDS].type != MSGPACK_OBJECT_ARRAY)
		return error_reply(si, RT_GET|RT_ERROR, cid, "oids must be an array");
	if (o->via.array.ptr[RI_GET_OIDS].via.array.size < 1)
		return error_reply(si, RT_GET|RT_ERROR, cid, "oids is an empty array");

	cri = get_client_requests_info(&ip, port, si);
	ci = get_cid_info(cri, cid);
	if (ci->n_oids != 0)
		return error_reply(si, RT_GET|RT_ERROR, cid, "duplicate request id");

	TAILQ_INIT(&oi);
	if ( (ci->n_oids = allocate_oid_info_list(&oi, &o->via.array.ptr[RI_GET_OIDS], ci)) == 0) {
		// XXX free allocated objects
		return error_reply(si, RT_GET|RT_ERROR, cid, "bad oid list");
	}
	TAILQ_CONCAT(&cri->oids_to_query, &oi, oid_list);

	PS.get_requests++;
	si->PS.get_requests++;
	maybe_query_destination(cri->dest);
	return 0;
}

