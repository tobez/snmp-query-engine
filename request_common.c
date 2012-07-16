/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

int
error_reply(struct socket_info *si, unsigned code, unsigned cid, char *error)
{
	msgpack_sbuffer* buffer = msgpack_sbuffer_new();
	msgpack_packer* pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	int l = strlen(error);

	msgpack_pack_array(pk, 3);
	msgpack_pack_unsigned_int(pk, code);
	msgpack_pack_unsigned_int(pk, cid);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, error, l);

	tcp_send(si, buffer->data, buffer->size);
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
	return -1;
}

int
msgpack_pack_named_int(msgpack_packer *pk, char *name, int64_t val)
{
	int l = strlen(name);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, name, l);
	msgpack_pack_int64(pk, val);
	/* XXX */
	return 0;
}

int
msgpack_pack_named_string(msgpack_packer *pk, char *name, char *val)
{
	int l = strlen(name);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, name, l);
	l = strlen(val);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, val, l);
	/* XXX */
	return 0;
}

int
msgpack_pack_string(msgpack_packer *pk, char *s)
{
	int l = strlen(s);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, s, l);
	/* XXX */
	return 0;
}

int
msgpack_pack_options(msgpack_packer *pk, struct client_requests_info *cri)
{
	msgpack_pack_map(pk, 12);
	msgpack_pack_named_string(pk, "ip", inet_ntoa(cri->dest->ip));
	msgpack_pack_named_int(pk, "port", cri->dest->port);
	msgpack_pack_named_string(pk, "community", cri->community);
	msgpack_pack_named_int(pk, "version", cri->version + 1);
	msgpack_pack_named_int(pk, "max_packets", cri->dest->max_packets_on_the_wire);
	msgpack_pack_named_int(pk, "max_req_size", cri->dest->max_request_packet_size);
	msgpack_pack_named_int(pk, "timeout", cri->timeout);
	msgpack_pack_named_int(pk, "retries", cri->retries);
	msgpack_pack_named_int(pk, "min_interval", cri->dest->min_interval);
	msgpack_pack_named_int(pk, "max_repetitions", cri->dest->max_repetitions);
	msgpack_pack_named_int(pk, "ignore_threshold", cri->dest->ignore_threshold);
	msgpack_pack_named_int(pk, "ignore_duration", cri->dest->ignore_duration);
	return 0;
}

static void inline
pack_error(msgpack_packer *pk, char *error)
{
	int l = strlen(error);
	msgpack_pack_array(pk, 1);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, error, l);
}

void
msgpack_pack_oid(struct msgpack_packer *pk, struct ber oid)
{
	char *stroid;
	int l;

	stroid = oid2str(oid);
	l = strlen(stroid);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, stroid, l);
}

void
msgpack_pack_ber(struct msgpack_packer *pk, struct ber value)
{
	unsigned char t;
	unsigned len, u32;
	unsigned long long u64;
	struct in_addr ip;
	char *strip;
	char unsupported[30]; /* "unsupported type 0xXX" */

	if (decode_type_len(&value, &t, &len) < 0)
		t = VAL_DECODE_ERROR;
	switch (t) {
	case AT_INTEGER:
	case AT_COUNTER:
	case AT_UNSIGNED:
		if (decode_integer(&value, len, &u32) < 0)	goto decode_error;
		msgpack_pack_uint64(pk, u32);
		break;
	case AT_STRING:
		msgpack_pack_raw(pk, len);
		msgpack_pack_raw_body(pk, value.b, len);
		break;
	case AT_NULL:
		msgpack_pack_nil(pk);
		break;
	case AT_TIMETICKS:
		if (decode_timeticks(&value, len, &u64) < 0)	goto decode_error;
		msgpack_pack_uint64(pk, u64);
		break;
	case AT_COUNTER64:
		if (decode_counter64(&value, len, &u64) < 0)	goto decode_error;
		msgpack_pack_uint64(pk, u64);
		break;
	case AT_IP_ADDRESS:
		if (decode_ipv4_address(&value, len, &ip) < 0)	goto decode_error;
		strip = inet_ntoa(ip);
		len = strlen(strip);
		msgpack_pack_raw(pk, len);
		msgpack_pack_raw_body(pk, strip, len);
		break;
	case AT_NO_SUCH_OBJECT:
		pack_error(pk, "no-such-object");
		break;
	case AT_NO_SUCH_INSTANCE:
		pack_error(pk, "no-such-instance");
		break;
	case AT_END_OF_MIB_VIEW:
		pack_error(pk, "end-of-mib");
		break;
	case VAL_TIMEOUT:
		pack_error(pk, "timeout");
		break;
	case VAL_MISSING:
		pack_error(pk, "missing");
		break;
decode_error:
	case VAL_DECODE_ERROR:
		pack_error(pk, "decode-error");
		break;
	case VAL_IGNORED:
		pack_error(pk, "ignored");
		break;
	default:
		snprintf(unsupported, 30, "unsupported type 0x%02x", t);
		pack_error(pk, unsupported);
	}
}
