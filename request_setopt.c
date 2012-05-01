#include "sqe.h"

/*
 * setopt request:
 * [ 0, $cid, $ip, $port, {options} ]
 *
 */

static void *option2index; /* a JudySL tree */

#define OPT_VERSION      1
#define OPT_COMMUNITY    2
#define OPT_MAX_PACKETS  3
#define OPT_MAX_REQ_SIZE 4
#define OPT_TIMEOUT      5
#define OPT_RETRIES      6

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
	o = &o->via.array.ptr[RI_SETOPT_OPT];
	for (i = 0; i < o->via.map.size; i++) {
		char name[256];
		Word_t *val;

		if (!object2string(&o->via.map.ptr[i].key, name, 256))
			return error_reply(si, RT_SETOPT|RT_ERROR, cid, "bad option key");
		JSLG(val, option2index, (unsigned char *)name);
		if (!val)
			return error_reply(si, RT_SETOPT|RT_ERROR, cid, "bad option key");
		switch (*val) {
		case OPT_VERSION:
			break;
		case OPT_COMMUNITY:
			break;
		case OPT_MAX_PACKETS:
			break;
		case OPT_MAX_REQ_SIZE:
			break;
		case OPT_TIMEOUT:
			break;
		case OPT_RETRIES:
			break;
		default:
			return error_reply(si, RT_SETOPT|RT_ERROR, cid, "bad option key");
		}
	}

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
