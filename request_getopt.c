/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

/*
 * getopt request:
 * [ RT_GETOPT, $cid, $ip, $port ]
 *
 * reply:
 * [ RT_GETOPT|RT_REPLY, $cid, { options } ]
 * where options has the following keys:
 * - ip: same as $ip in the request
 * - port: same as $port in the request
 * - community: snmp community
 * - version: snmp version (1 or 2)
 * - max_packets: max packets on the wire to this destination
 * - max_req_size: max request packet size, in bytes, including IP & UDP header
 * - timeout: timeout waiting for reply in milliseconds
 * - retries: number of times to send a request before giving up
 * - XXX more stuff
 *
 */

int
handle_getopt_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	unsigned port = 65536;
	struct in_addr ip;
	struct client_requests_info *cri;
	struct destination *d;
	msgpack_sbuffer* buffer;
	msgpack_packer* pk;

	if (o->via.array.size != 4)
		return error_reply(si, RT_GETOPT|RT_ERROR, cid, "bad request length");

	if (o->via.array.ptr[RI_GETOPT_PORT].type == MSGPACK_OBJECT_POSITIVE_INTEGER)
		port = o->via.array.ptr[RI_GETOPT_PORT].via.u64;
	if (port > 65535)
		return error_reply(si, RT_GETOPT|RT_ERROR, cid, "bad port number");

	if (!object2ip(&o->via.array.ptr[RI_GETOPT_IP], &ip))
		return error_reply(si, RT_GETOPT|RT_ERROR, cid, "bad IP");

	PS.getopt_requests++;
	si->PS.getopt_requests++;

	cri = get_client_requests_info(&ip, port, si);
	d = cri->dest;

	buffer = msgpack_sbuffer_new();
	pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	msgpack_pack_array(pk, 3);
	msgpack_pack_int(pk, RT_GETOPT|RT_REPLY);
	msgpack_pack_int(pk, cid);
	msgpack_pack_options(pk, cri);

	tcp_send(si, buffer->data, buffer->size);
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
	return 0;
}
