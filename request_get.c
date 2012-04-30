#include "sqe.h"

/*
 * get request:
 * [ 0, $cid, $ip, $port, $version, $community, [$oids], {other parameters} ]
 *
 */

int
handle_get_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	unsigned ver = 0;
	unsigned port = 65536;
	char community[256];
	struct in_addr ip;
	struct client_requests_info *cri;
	struct cid_info *ci;
	struct oid_info_head oi;

	if (o->via.array.size < 7 || o->via.array.size > 8)
		return error_reply(si, RT_GET|RT_ERROR, cid, "bad request length");

	if (o->via.array.ptr[RI_GET_SNMP_VER].type == MSGPACK_OBJECT_POSITIVE_INTEGER)
		ver = o->via.array.ptr[RI_GET_SNMP_VER].via.u64;
	if (ver != 1 && ver != 2)
		return error_reply(si, RT_GET|RT_ERROR, cid, "bad SNMP version");

	if (o->via.array.ptr[RI_GET_PORT].type == MSGPACK_OBJECT_POSITIVE_INTEGER)
		port = o->via.array.ptr[RI_GET_PORT].via.u64;
	if (port > 65535)
		return error_reply(si, RT_GET|RT_ERROR, cid, "bad port number");

	if (!object2ip(&o->via.array.ptr[RI_GET_IP], &ip))
		return error_reply(si, RT_GET|RT_ERROR, cid, "bad IP");

	if (!object2string(&o->via.array.ptr[RI_GET_COMMUNITY], community, 256))
		return error_reply(si, RT_GET|RT_ERROR, cid, "bad community");

	if (o->via.array.ptr[RI_GET_OIDS].type != MSGPACK_OBJECT_ARRAY)
		return error_reply(si, RT_GET|RT_ERROR, cid, "oids must be an array");
	if (o->via.array.ptr[RI_GET_OIDS].via.array.size < 1)
		return error_reply(si, RT_GET|RT_ERROR, cid, "oids is an empty array");

	cri = get_client_requests_info(&ip, port, si->fd);
	cri->si = si;
	strcpy(cri->dest->community, community);
	cri->dest->version = ver - 1;
	ci = get_cid_info(cri, cid);
	if (ci->n_oids != 0)
		return error_reply(si, RT_GET|RT_ERROR, cid, "duplicate request id");

	TAILQ_INIT(&oi);
	if ( (ci->n_oids = allocate_oid_info_list(&oi, &o->via.array.ptr[RI_GET_OIDS], ci)) == 0) {
		// XXX free allocated objects
		return error_reply(si, RT_GET|RT_ERROR, cid, "bad oid list");
	}
	TAILQ_CONCAT(&cri->oids_to_query, &oi, oid_list);

	maybe_query_destination(cri->dest);
	return 0;
}

