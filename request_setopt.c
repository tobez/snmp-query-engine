#include "sqe.h"

/*
 * setopt request:
 * [ 0, $cid, $ip, $port, {options} ]
 *
 */

static void *option2index; /* a JudySL tree */

#define OPT_VERSION       1
#define OPT_COMMUNITY     2
#define OPT_MAX_PACKETS   3
#define OPT_MAX_REQ_SIZE  4
#define OPT_TIMEOUT       5
#define OPT_RETRIES       6
#define OPT_MIN_INTERVAL  7
#define OPT_REQUEST_DELAY 8

static void
build_option2index(void)
{
	Word_t *val;

	JSLI(val, option2index, (unsigned char *)"version");
	if (val == PJERR) croak(2, "build_option2index: JSLI(version) failed");
	*val = OPT_VERSION;

	JSLI(val, option2index, (unsigned char *)"community");
	if (val == PJERR) croak(2, "build_option2index: JSLI(community) failed");
	*val = OPT_COMMUNITY;

	JSLI(val, option2index, (unsigned char *)"max_packets");
	if (val == PJERR) croak(2, "build_option2index: JSLI(max_packets) failed");
	*val = OPT_MAX_PACKETS;

	JSLI(val, option2index, (unsigned char *)"max_req_size");
	if (val == PJERR) croak(2, "build_option2index: JSLI(max_req_size) failed");
	*val = OPT_MAX_REQ_SIZE;

	JSLI(val, option2index, (unsigned char *)"timeout");
	if (val == PJERR) croak(2, "build_option2index: JSLI(timeout) failed");
	*val = OPT_TIMEOUT;

	JSLI(val, option2index, (unsigned char *)"retries");
	if (val == PJERR) croak(2, "build_option2index: JSLI(retries) failed");
	*val = OPT_RETRIES;

	JSLI(val, option2index, (unsigned char *)"min_interval");
	if (val == PJERR) croak(2, "build_option2index: JSLI(min_interval) failed");
	*val = OPT_MIN_INTERVAL;

	JSLI(val, option2index, (unsigned char *)"request_delay");
	if (val == PJERR) croak(2, "build_option2index: JSLI(request_delay) failed");
	*val = OPT_REQUEST_DELAY;
}

int
handle_setopt_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	unsigned port = 65536;
	struct in_addr ip;
	struct client_requests_info *cri;
	struct destination d;
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

	cri = get_client_requests_info(&ip, port, si->fd);
	memcpy(&d, cri->dest, sizeof(d));

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
		case OPT_VERSION:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || (v->via.u64 != 1 && v->via.u64 != 2))
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid SNMP version");
			d.version = v->via.u64 - 1;
			break;
		case OPT_COMMUNITY:
			if (!object2string(v, d.community, 256))
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid SNMP community");
			break;
		case OPT_MAX_PACKETS:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 < 1 || v->via.u64 > 1000)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid max packets");
			d.max_packets_on_the_wire = v->via.u64;
			break;
		case OPT_MAX_REQ_SIZE:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 < 500 || v->via.u64 > 50000)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid max request size");
			d.max_request_packet_size = v->via.u64;
			break;
		case OPT_TIMEOUT:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 > 30000)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid timeout");
			d.timeout = v->via.u64;
			break;
		case OPT_RETRIES:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 < 1 || v->via.u64 > 10)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid retries");
			d.retries = v->via.u64;
			break;
		case OPT_MIN_INTERVAL:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 > 10000)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid min interval");
			d.min_interval = v->via.u64;
			break;
		case OPT_REQUEST_DELAY:
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || v->via.u64 > 3000)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid request delay");
			d.request_delay = v->via.u64;
			break;
		default:
			return error_reply(si, RT_SETOPT|RT_ERROR, cid, "bad option key");
		}
	}

	PS.setopt_requests++;
	si->PS.setopt_requests++;

	memcpy(cri->dest, &d, sizeof(d)); /* This is safe to do, I am sure */
	buffer = msgpack_sbuffer_new();
	pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	msgpack_pack_array(pk, 3);
	msgpack_pack_int(pk, RT_SETOPT|RT_REPLY);
	msgpack_pack_int(pk, cid);
	msgpack_pack_options(pk, &d);

	tcp_send(si, buffer->data, buffer->size);
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
	return 0;
}
