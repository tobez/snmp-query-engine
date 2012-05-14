#include "sqe.h"

/*
 * info request:
 * [ 0, $cid ]
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

	STAT(snmp_retries);
	STAT(snmp_sends);
	STAT(snmp_v1_sends);
	STAT(snmp_v2c_sends);
	STAT(snmp_timeouts);
	STAT(udp_timeouts);
	STAT(bad_snmp_responses);
	STAT(good_snmp_responses);
	STAT(oids_requested);
	STAT(oids_returned_from_snmp);
	STAT(oids_returned_to_client);

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

	if (o->via.array.size != 2)
		return error_reply(si, RT_INFO|RT_ERROR, cid, "bad request length");

	PS.info_requests++;
	si->PS.info_requests++;

	PS.uptime = ms_passed_since(&prog_start);
	si->PS.uptime = ms_passed_since(&si->created);

	buffer = msgpack_sbuffer_new();
	pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	msgpack_pack_array(pk, 3);
	msgpack_pack_int(pk, RT_INFO|RT_REPLY);
	msgpack_pack_int(pk, cid);
	msgpack_pack_map(pk, 2);

	key = "global";
	l = strlen(key);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, key, l);
	msgpack_pack_map(pk, pack_stats(&PS, NULL));
	pack_stats(&PS, pk);

	key = "connection";
	l = strlen(key);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, key, l);
	msgpack_pack_map(pk, pack_stats(&si->PS, NULL));
	pack_stats(&si->PS, pk);

	tcp_send(si, buffer->data, buffer->size);
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
	return 0;
}
