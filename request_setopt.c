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
#define OPT_engineid			 15
#define OPT_username			 16
#define OPT_authprotocol		 17
#define OPT_authpassword		 18
#define OPT_authkul			 	 19
#define OPT_privprotocol		 20
#define OPT_privpassword		 21
#define OPT_privkul			 	 22

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
	ADD(engineid)
	ADD(username)
	ADD(authprotocol)
	ADD(authpassword)
	ADD(authkul)
	ADD(privprotocol)
	ADD(privpassword)
	ADD(privkul)
	#undef ADD
}

int
handle_setopt_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	unsigned port = 65536;
	struct in_addr ip;
	struct client_requests_info *cri;
	struct destination d;
	struct snmpv3info v3;
	int need_v3 = 0;
	struct client_requests_info c;
	msgpack_sbuffer* buffer;
	msgpack_packer* pk;
	msgpack_object *h, *v;
	msgpack_object_type t;
	int i;
	int seen_authpassword = 0;
	int seen_authkul = 0;
	int seen_privpassword = 0;
	int seen_privkul = 0;

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
	bzero(&v3, sizeof(v3));
	if (c.v3) {
		memcpy(&v3, cri->v3, sizeof(v3));
		need_v3 = 1;
	}

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
			if (t != MSGPACK_OBJECT_POSITIVE_INTEGER || (v->via.u64 < 1 && v->via.u64 > 3))
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid SNMP version");
			c.version = v->via.u64;
            if (c.version != 3)
                c.version--;
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
		case OPT_engineid:
			v3.engine_id_len = object_hexstring_to_buffer(v, v3.engine_id, V3O_ENGINE_ID_MAXLEN);
			if (v3.engine_id_len < 0)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid engineid hexstring");
			need_v3 = 1;
			break;
		case OPT_username:
			if (!object2string(v, v3.username, V3O_USERNAME_MAXSIZE))
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid username");
			need_v3 = 1;
			break;
		case OPT_authprotocol:
			if (object_string_eq(v, "md5")) {
				v3.auth_proto = V3O_AUTH_PROTO_MD5;
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "auth protocol md5 is not implemented");
			} else if (object_string_eq(v, "sha1")) {
				v3.auth_proto = V3O_AUTH_PROTO_SHA1;
			} else if (object_string_eq(v, "sha")) {
				v3.auth_proto = V3O_AUTH_PROTO_SHA1;
			} else {
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid auth protocol");
			}
			need_v3 = 1;
			break;
		case OPT_authpassword:
			if (!object2string(v, v3.authpass, V3O_AUTHPASS_MAXSIZE))
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid auth password");
			seen_authpassword = 1;
			v3.authkul_len = 0;
			need_v3 = 1;
			break;
		case OPT_authkul:
			v3.authkul_len = object_hexstring_to_buffer(v, v3.authkul, V3O_AUTHKUL_MAXSIZE);
			if (v3.authkul_len < 0)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid authkul hexstring");
			seen_authkul = 1;
			v3.authpass[0] = 0;
			need_v3 = 1;
			break;
		case OPT_privprotocol:
			if (object_string_eq(v, "des")) {
				v3.priv_proto = V3O_PRIV_PROTO_DES;
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "priv protocol des is not implemented");
			} else if (object_string_eq(v, "aes")) {
				v3.priv_proto = V3O_PRIV_PROTO_AES;
			} else if (object_string_eq(v, "aes128")) {
				v3.priv_proto = V3O_PRIV_PROTO_AES128;
			} else if (object_string_eq(v, "aes192")) {
				v3.priv_proto = V3O_PRIV_PROTO_AES192;
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "priv protocol aes192 is not implemented");
			} else if (object_string_eq(v, "aes256")) {
				v3.priv_proto = V3O_PRIV_PROTO_AES256;
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "priv protocol aes256 is not implemented");
			} else if (object_string_eq(v, "aes192c")) {
				v3.priv_proto = V3O_PRIV_PROTO_AES192_CISCO;
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "priv protocol aes192c is not implemented");
			} else if (object_string_eq(v, "aes256c")) {
				v3.priv_proto = V3O_PRIV_PROTO_AES256_CISCO;
			} else {
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid priv protocol");
			}
			need_v3 = 1;
			break;
		case OPT_privpassword:
			if (!object2string(v, v3.privpass, V3O_PRIVPASS_MAXSIZE))
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid priv password");
			seen_privpassword = 1;
			v3.privkul_len = 0;
			need_v3 = 1;
			break;
		case OPT_privkul:
			v3.privkul_len = object_hexstring_to_buffer(v, v3.privkul, V3O_PRIVKUL_MAXSIZE);
			if (v3.privkul_len < 0)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "invalid privkul hexstring");
			seen_privkul = 1;
			v3.privpass[0] = 0;
			need_v3 = 1;
			break;
		default:
			return error_reply(si, RT_SETOPT|RT_ERROR, cid, "bad option key");
		}
	}

	if (seen_authpassword && seen_authkul)
		return error_reply(si, RT_SETOPT|RT_ERROR, cid, "authpassword and authkul are mutually exclusive");
	if (seen_privpassword && seen_privkul)
		return error_reply(si, RT_SETOPT|RT_ERROR, cid, "privpassword and privkul are mutually exclusive");

	if (need_v3 && v3.authpass[0]) {
		char *err;

        if (!password_to_kul(v3.auth_proto,
                             v3.authpass,
							 strlen(v3.authpass),
                             v3.engine_id,
							 v3.engine_id_len,
							 v3.authkul,
                             V3O_AUTHKUL_MAXSIZE,
                             &v3.authkul_len,
                             &err))
		{
            fprintf(stderr, "handle_setopt_request: authkul calculation error: "
                    "password_to_kul: %s\n", err);
            return error_reply(si, RT_SETOPT | RT_ERROR, cid, "authpass to kul calculation error");
        }
    }

	if (need_v3 && v3.privpass[0]) {
		char *err;

        if (!password_to_kul(v3.auth_proto,
                             v3.privpass,
							 strlen(v3.privpass),
                             v3.engine_id,
							 v3.engine_id_len,
							 v3.privkul,
                             V3O_PRIVKUL_MAXSIZE,
                             &v3.privkul_len,
                             &err))
		{
            fprintf(stderr, "handle_setopt_request: privkul calculation error: "
                    "password_to_kul: %s\n", err);
            return error_reply(si, RT_SETOPT | RT_ERROR, cid, "privpass to kul calculation error");
        }

        if (!expand_kul(v3.auth_proto,
                        v3.priv_proto,
                        v3.privkul,
                        v3.privkul_len,
                        v3.engine_id,
                        v3.engine_id_len,
                        v3.x_privkul,
                        V3O_PRIVKUL_MAXSIZE,
                        &v3.x_privkul_len,
                        &err))
		{
            fprintf(stderr, "handle_setopt_request: privkul calculation error: "
                    "expand_kul: %s\n", err);
            return error_reply(si, RT_SETOPT | RT_ERROR, cid, "expand kul calculation error");
        }
    }

    PS.setopt_requests++;
    si->PS.setopt_requests++;

    memcpy(cri, &c, sizeof(c));       /* This is safe to do, I am sure */
    memcpy(cri->dest, &d, sizeof(d)); /* This is safe to do, I am sure */
    if (need_v3) {
		v3.msg_max_size = d.max_reply_packet_size; // always just copy
		if (!cri->v3) {
			cri->v3 = malloc(sizeof(v3));
			if (!cri->v3)
				return error_reply(si, RT_SETOPT|RT_ERROR, cid, "malloc v3 problem");
		}
		memcpy(cri->v3, &v3, sizeof(v3));
	}

	buffer = msgpack_sbuffer_new();
	pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	msgpack_pack_array(pk, 3);
	msgpack_pack_int(pk, RT_SETOPT|RT_REPLY);
	msgpack_pack_int(pk, cid);
	msgpack_pack_options(pk, cri);

	tcp_send(si, buffer->data, buffer->size);
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
	return 0;
}
