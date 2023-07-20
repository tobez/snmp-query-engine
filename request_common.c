/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2013, Anton Berezin <tobez@tobez.org>
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
	msgpack_pack_bin(pk, l);
	msgpack_pack_bin_body(pk, error, l);

	tcp_send(si, buffer->data, buffer->size);
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
	return -1;
}

int
msgpack_pack_named_int(msgpack_packer *pk, char *name, int64_t val)
{
	int l = strlen(name);
	msgpack_pack_bin(pk, l);
	msgpack_pack_bin_body(pk, name, l);
	msgpack_pack_int64(pk, val);
	/* XXX */
	return 0;
}

int
msgpack_pack_named_string(msgpack_packer *pk, char *name, char *val)
{
	int l = strlen(name);
	msgpack_pack_bin(pk, l);
	msgpack_pack_bin_body(pk, name, l);
	l = strlen(val);
	msgpack_pack_bin(pk, l);
	msgpack_pack_bin_body(pk, val, l);
	/* XXX */
	return 0;
}

int
msgpack_pack_string(msgpack_packer *pk, char *s)
{
	int l = strlen(s);
	msgpack_pack_bin(pk, l);
	msgpack_pack_bin_body(pk, s, l);
	/* XXX */
	return 0;
}

int
msgpack_pack_named_hex_buffer(msgpack_packer *pk, char *name, unsigned char *buf, int sz)
{
	char *s = malloc(sz*2 + 1);
	char *t;
	if (!s)	return -1;
	t = s;
	while (sz) {
		int n = (*buf) >> 4;
		if (n < 10) *t++ = n + '0'; else *t++ = n - 10 + 'a';
		n = (*buf) & 0x0f;
		if (n < 10) *t++ = n + '0'; else *t++ = n - 10 + 'a';
		buf++;
		sz--;
	}
	*t = 0;
	msgpack_pack_named_string(pk, name, s);
	free(s);
	return 0;
}

int
msgpack_pack_options(msgpack_packer *pk, struct client_requests_info *cri)
{
	int map_size = 15;

	if (cri->v3)
		map_size += 6;

	msgpack_pack_map(pk, map_size);
	msgpack_pack_named_string(pk, "ip", inet_ntoa(cri->dest->ip));
	msgpack_pack_named_int(pk, "port", cri->dest->port);
	msgpack_pack_named_string(pk, "community", cri->community);
	msgpack_pack_named_int(pk, "version", cri->version <= 1 ? cri->version + 1 : cri->version);
	msgpack_pack_named_int(pk, "max_packets", cri->dest->max_packets_on_the_wire);
	msgpack_pack_named_int(pk, "max_req_size", cri->dest->max_request_packet_size);
	msgpack_pack_named_int(pk, "max_reply_size", cri->dest->max_reply_packet_size);
	msgpack_pack_named_int(pk, "estimated_value_size", cri->dest->estimated_value_size);
	msgpack_pack_named_int(pk, "max_oids_per_request", cri->dest->max_oids_per_request);
	msgpack_pack_named_int(pk, "timeout", cri->timeout);
	msgpack_pack_named_int(pk, "retries", cri->retries);
	msgpack_pack_named_int(pk, "min_interval", cri->dest->min_interval);
	msgpack_pack_named_int(pk, "max_repetitions", cri->dest->max_repetitions);
	msgpack_pack_named_int(pk, "ignore_threshold", cri->dest->ignore_threshold);
	msgpack_pack_named_int(pk, "ignore_duration", cri->dest->ignore_duration);
	if (cri->v3) {
		char *s = "";
		msgpack_pack_named_string(pk, "username", cri->v3->username);
		msgpack_pack_named_hex_buffer(pk, "engineid", cri->v3->engine_id, cri->v3->engine_id_len);
		switch (cri->v3->auth_proto) {
		case V3O_AUTH_PROTO_MD5:
			s = "md5";
			break;
		case V3O_AUTH_PROTO_SHA1:
			s = "sha1";
			break;
		default:
			s = "?";
			break;
		}
		msgpack_pack_named_string(pk, "authprotocol", s);
		msgpack_pack_named_hex_buffer(pk, "authkul", cri->v3->authkul, cri->v3->authkul_len);
		switch (cri->v3->priv_proto) {
		case V3O_PRIV_PROTO_DES:
		case V3O_PRIV_PROTO_AES128:
			s = "aes";
			break;
		case V3O_PRIV_PROTO_AES192:
			s = "aes192";
			break;
		case V3O_PRIV_PROTO_AES256:
			s = "aes256";
			break;
		case V3O_PRIV_PROTO_AES192_CISCO:
			s = "aes192c";
			break;
		case V3O_PRIV_PROTO_AES256_CISCO:
			s = "aes256c";
			break;
		default:
			s = "?";
			break;
		}
		msgpack_pack_named_string(pk, "privprotocol", s);
		msgpack_pack_named_hex_buffer(pk, "privkul", cri->v3->privkul, cri->v3->privkul_len);
	}
	return 0;
}

static void inline
pack_error(msgpack_packer *pk, char *error)
{
	int l = strlen(error);
	msgpack_pack_array(pk, 1);
	msgpack_pack_bin(pk, l);
	msgpack_pack_bin_body(pk, error, l);
}

void
msgpack_pack_oid(struct msgpack_packer *pk, struct ber oid)
{
	char *stroid;
	int l;

	stroid = oid2str(oid);
	l = strlen(stroid);
	msgpack_pack_bin(pk, l);
	msgpack_pack_bin_body(pk, stroid, l);
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
		if (t == AT_INTEGER) {
			/* XXX quick fix, but should be correct! */
			if (len == 1 && (u32 & 0x80)) {
				msgpack_pack_int64(pk, ((int32_t)(uint32_t)u32) - 0x100);
			} else if (len == 2 && (u32 & 0x8000)) {
				msgpack_pack_int64(pk, ((int32_t)(uint32_t)u32) - 0x10000);
			} else if (len == 3 && (u32 & 0x800000)) {
				msgpack_pack_int64(pk, ((int32_t)(uint32_t)u32) - 0x1000000);
			} else {
				msgpack_pack_int64(pk, (int32_t)(uint32_t)u32);
			}
		} else {
			msgpack_pack_uint64(pk, u32);
		}
		break;
	case AT_STRING:
		msgpack_pack_bin(pk, len);
		msgpack_pack_bin_body(pk, value.b, len);
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
		msgpack_pack_bin(pk, len);
		msgpack_pack_bin_body(pk, strip, len);
		break;
	case AT_OID:
		msgpack_pack_oid(pk, value);
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
	case VAL_NON_INCREASING:
		pack_error(pk, "non-increasing");
		break;
	case VAL_STRING_ERROR:
		msgpack_pack_array(pk, 1);
		msgpack_pack_bin(pk, len);
		msgpack_pack_bin_body(pk, value.b, len);
		break;
	default:
		snprintf(unsupported, 30, "unsupported type 0x%02x", t);
		pack_error(pk, unsupported);
	}
}
