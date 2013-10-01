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
 * setopt request:
 * [ 0, $cid, $ip, $port, {options} ]
 *
 */

static void *option2index; /* a JudySL tree */

#define OPT_version               1
#define OPT_community             2
#define OPT_max_packets           3
#define OPT_max_req_size          4
#define OPT_timeout               5
#define OPT_retries               6
#define OPT_min_interval          7
#define OPT_max_repetitions       8
#define OPT_ignore_threshold      9
#define OPT_ignore_duration      10
#define OPT_max_reply_size       11
#define OPT_estimated_value_size 12
#define OPT_max_oids_per_request 13
#define OPT_global_max_packets   14

static void
build_option2index(void)
{
	Word_t *val;

	#define ADD(var) JSLI(val, option2index, (unsigned char *)#var); if (val == PJERR) croak(2, "build_option2index: JSLI(" #var ") failed"); *val = OPT_##var;
	ADD(version);
	ADD(community);
	ADD(max_packets);
	ADD(global_max_packets);
	ADD(max_req_size);
	ADD(max_reply_size);
	ADD(estimated_value_size);
	ADD(max_oids_per_request);
	ADD(timeout);
	ADD(retries);
	ADD(min_interval);
	ADD(max_repetitions);
	ADD(ignore_threshold);
	ADD(ignore_duration);
	#undef ADD
}

int
handle_setopt_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	unsigned port = 65536;
	struct in_addr ip;
	struct client_requests_info *cri;
	struct destination d;
	struct client_requests_info c;
	msgpack_sbuffer* buffer;
	msgpack_packer* pk;
	msgpack_object *h, *v;
	msgpack_object_type t;
	int i;

	if (o->via.array.size != 5)
		return error_reply(si, RT_SETOPT|RT_ERROR, cid, "bad request length");

	if (o->via.array.ptr[RI_SETOPT_PORT].type == MSGPACK_OBJECT_POSITIVE_INTEGER)
		port = o->via.array.ptr[RI_SETOPT_PORT].via.u64;
	if (port > 65535)
		return error_reply(si, RT_SETOPT|RT_ERROR, cid, "bad port number");

	if (!object2ip(&o->via.array.ptr[RI_SETOPT_IP], &ip))
		return error_reply(si, RT_SETOPT|RT_ERROR, cid, "bad IP");

	if (o->via.array.ptr[RI_SETOPT_OPT].type != MSGPACK_OBJECT_MAP)
		return error_reply(si, RT_SETOPT|RT_ERROR, cid, "options is not a map");

	cri = get_client_requests_info(&ip, port, si);
	memcpy(&d, cri->dest, sizeof(d));
	memcpy(&c, cri, sizeof(c));

	if (!option2index)
		build_option2index();
	h = &o->via.array.ptr[RI_SETOPT_OPT];
	for (i = 0; i < h->via.map.size; i++) {
		char name[256];
		Word_t *val;

		if (!object2string(&h->via.map.ptr[i].key, name, 256))
			return error_reply(si, RT_SETOPT|RT_ERROR, cid, "bad option key");
		JSLG(val, option2index, (unsigned char *)name);
		if (!val)
			return error_reply(si, RT_SETOPT|RT_ERROR, cid, "bad option key");
		v = &h->via.map.ptr[i].val;
		t = v->type;
		switch (*val) {
		case OPT_version:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || (v->via.u64 != 1 && v->via.u64 != 2))
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid SNMP version");
			c.version = v->via.u64 - 1;
			break;
		case OPT_community:
			if (!object2string(v, c.community, 256))
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid SNMP community");
			break;
		case OPT_max_packets:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 < 1 || v->via.u64 > 1000)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid max packets");
			d.max_packets_on_the_wire = v->via.u64;
			break;
		case OPT_global_max_packets:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 < 1 || v->via.u64 > 2000000)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid global max packets");
			PS.max_packets_on_the_wire = v->via.u64;
			break;
		case OPT_max_req_size:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 < 500 || v->via.u64 > 50000)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid max request size");
			d.max_request_packet_size = v->via.u64;
			break;
		case OPT_max_reply_size:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 < 500 || v->via.u64 > 50000)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid max reply size");
			d.max_reply_packet_size = v->via.u64;
			break;
		case OPT_estimated_value_size:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 < 1 || v->via.u64 > 1024)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid estimated value size");
			d.estimated_value_size = v->via.u64;
			break;
		case OPT_max_oids_per_request:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 < 1 || v->via.u64 > 1024)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid max oids per request");
			d.max_oids_per_request = v->via.u64;
			break;
		case OPT_timeout:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 > 30000)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid timeout");
			c.timeout = v->via.u64;
			break;
		case OPT_retries:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 < 1 || v->via.u64 > 10)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid retries");
			c.retries = v->via.u64;
			break;
		case OPT_min_interval:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 > 10000)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid min interval");
			d.min_interval = v->via.u64;
			break;
		case OPT_max_repetitions:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 < 1 || v->via.u64 > 255)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid max repetitions");
			d.max_repetitions = v->via.u64;
			break;
		case OPT_ignore_threshold:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 > 1000)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid ignore threshold");
			d.ignore_threshold = v->via.u64;
			if (cri->dest->ignore_threshold != d.ignore_threshold)
				bzero(&d.ignore_until, sizeof(cri->dest->ignore_until));
			break;
		case OPT_ignore_duration:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 > 86400000)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid ignore duration");
			d.ignore_duration = v->via.u64;
			if (cri->dest->ignore_duration != d.ignore_duration)
				bzero(&d.ignore_until, sizeof(cri->dest->ignore_until));
			break;
		default:
			return error_reply(si, RT_SETOPT|RT_ERROR, cid, "bad option key");
		}
	}

	PS.setopt_requests++;
	si->PS.setopt_requests++;

	memcpy(cri, &c, sizeof(c));       /* This is safe to do, I am sure */
	memcpy(cri->dest, &d, sizeof(d)); /* This is safe to do, I am sure */
	buffer = msgpack_sbuffer_new();
	pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	msgpack_pack_array(pk, 3);
	msgpack_pack_int(pk, RT_SETOPT|RT_REPLY);
	msgpack_pack_int(pk, cid);
	msgpack_pack_options(pk, &c);

	tcp_send(si, buffer->data, buffer->size);
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
	return 0;
}
