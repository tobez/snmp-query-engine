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
 * info request:
 * [ 0, $cid ]
 *
 * dest_info request:
 * [ RT_DEST_INFO, $cid, $ip, $port ]
 *
 */

static int
pack_stats(struct program_stats *PS, msgpack_packer *pk)
{
	int n = 0;

	#define STAT(what) if (PS->what >= 0) { n++; if (pk) msgpack_pack_named_int(pk, #what, PS->what); }

	STAT(active_client_connections);
	STAT(total_client_connections);

	STAT(client_requests);
	STAT(invalid_requests);
	STAT(setopt_requests);
	STAT(getopt_requests);
	STAT(info_requests);
	STAT(get_requests);
	STAT(gettable_requests);
	STAT(dest_info_requests);

	STAT(snmp_retries);
	STAT(snmp_sends);
	STAT(snmp_v1_sends);
	STAT(snmp_v2c_sends);
	STAT(snmp_timeouts);
	STAT(udp_timeouts);
	STAT(bad_snmp_responses);
	STAT(good_snmp_responses);
	STAT(oids_non_increasing);
	STAT(oids_requested);
	STAT(oids_returned_from_snmp);
	STAT(oids_returned_to_client);
	STAT(oids_ignored);

	STAT(octets_received);
	STAT(octets_sent);

	STAT(active_timers_sec);
	STAT(active_timers_usec);
	STAT(total_timers_sec);
	STAT(total_timers_usec);
	STAT(uptime);

	STAT(active_sid_infos);
	STAT(total_sid_infos);
	STAT(active_oid_infos);
	STAT(total_oid_infos);
	STAT(active_cid_infos);
	STAT(total_cid_infos);
	STAT(active_cr_infos);
	STAT(total_cr_infos);

	STAT(destination_throttles);
	STAT(destination_ignores);

	STAT(udp_receive_buffer_size);
	STAT(udp_send_buffer_size);
	STAT(udp_send_buffer_overflow);
	STAT(packets_on_the_wire);
	STAT(max_packets_on_the_wire);
	STAT(global_throttles);
	STAT(program_version);

	#undef STAT
	return n;
}

int
handle_info_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	msgpack_sbuffer* buffer;
	msgpack_packer* pk;
	char *key;
	int l;

	if (o->via.array.size < 2)
		return error_reply(si, RT_INFO|RT_ERROR, cid, "bad request length");

	PS.info_requests++;
	si->PS.info_requests++;

	buffer = msgpack_sbuffer_new();
	pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	msgpack_pack_array(pk, 3);
	msgpack_pack_int(pk, RT_INFO|RT_REPLY);
	msgpack_pack_int(pk, cid);

	if (o->via.array.size == 3 &&
		o->via.array.ptr[2].type == MSGPACK_OBJECT_POSITIVE_INTEGER)
	{
		switch (o->via.array.ptr[2].via.u64) {
		case 1: /* dump destinations */
			dump_all_destinations(pk);
			goto send;
		}
	}

	PS.uptime = ms_passed_since(&prog_start);
	si->PS.uptime = ms_passed_since(&si->created);

	msgpack_pack_map(pk, 2);

	key = "global";
	l = strlen(key);
	msgpack_pack_bin(pk, l);
	msgpack_pack_bin_body(pk, key, l);
	msgpack_pack_map(pk, pack_stats(&PS, NULL));
	pack_stats(&PS, pk);

	key = "connection";
	l = strlen(key);
	msgpack_pack_bin(pk, l);
	msgpack_pack_bin_body(pk, key, l);
	msgpack_pack_map(pk, pack_stats(&si->PS, NULL));
	pack_stats(&si->PS, pk);

send:
	tcp_send(si, buffer->data, buffer->size);
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
	return 0;
}

static int
pack_dest_stats(struct destination *dest, msgpack_packer *pk)
{
	int n = 0;

	#define STAT(what) if (dest->what >= 0) { n++; if (pk) msgpack_pack_named_int(pk, #what, dest->what); }

	STAT(octets_received);
	STAT(octets_sent);

	#undef STAT
	return n;
}

int
handle_dest_info_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	msgpack_sbuffer* buffer;
	msgpack_packer* pk;
	unsigned port = 65536;
	struct in_addr ip;
	struct client_requests_info *cri;

	if (o->via.array.size != 4)
		return error_reply(si, RT_DEST_INFO|RT_ERROR, cid, "bad request length");

	if (o->via.array.ptr[RI_DEST_INFO_PORT].type == MSGPACK_OBJECT_POSITIVE_INTEGER)
		port = o->via.array.ptr[RI_DEST_INFO_PORT].via.u64;
	if (port > 65535)
		return error_reply(si, RT_DEST_INFO|RT_ERROR, cid, "bad port number");

	if (!object2ip(&o->via.array.ptr[RI_DEST_INFO_IP], &ip))
		return error_reply(si, RT_DEST_INFO|RT_ERROR, cid, "bad IP");

	PS.dest_info_requests++;
	si->PS.dest_info_requests++;

	buffer = msgpack_sbuffer_new();
	pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	msgpack_pack_array(pk, 3);
	msgpack_pack_int(pk, RT_DEST_INFO|RT_REPLY);
	msgpack_pack_int(pk, cid);

	cri = get_client_requests_info(&ip, port, si);
	msgpack_pack_map(pk, pack_dest_stats(cri->dest, NULL));
	pack_dest_stats(cri->dest, pk);

	tcp_send(si, buffer->data, buffer->size);
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
	return 0;
}
