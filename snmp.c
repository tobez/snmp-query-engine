/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2014, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

#include <openssl/evp.h>

static struct socket_info *snmp = NULL;

static void
snmp_process_datagram(struct socket_info *snmp, struct sockaddr_in *from, char *buf, int n)
{
	struct ber enc, *e;
	unsigned char t;
	unsigned l;
	unsigned sid, mid;
	unsigned version;
	char *trace;
	struct destination *dest;
	struct sid_info *si;
	char peer[64];

	snprintf(peer, sizeof(peer), "%s:%d", inet_ntoa(from->sin_addr),
	    ntohs(from->sin_port));

	PS.octets_received += n;
	dest = find_destination(&from->sin_addr, ntohs(from->sin_port));
	if (!dest) {
		log_warn("destination not known, ignoring packet", "peer", peer, NULL);
		return;
	}
	dest->octets_received += n;
	dest->packets_on_the_wire--;
	if (dest->packets_on_the_wire < 0)
		dest->packets_on_the_wire = 0;
	PS.packets_on_the_wire--;
	if (PS.packets_on_the_wire < 0)
		PS.packets_on_the_wire = 0;

	enc = ber_init(buf, n); e = &enc;

	#define CHECK(prob, val) if ((val) < 0) { trace = "decoding " # prob; goto bad_snmp_packet; }
	CHECK("start sequence", decode_sequence(e, NULL));
	CHECK("version", decode_integer(e, -1, &version));

	if (version != 3) {
        trace = "community type/len";
        if (decode_type_len(e, &t, &l) < 0)
          goto bad_snmp_packet;
        trace = "community type";
        if (t != AT_STRING)
          goto bad_snmp_packet;
        e->b += l;
        e->len += l; // XXX skip community

		CHECK("PDU", decode_composite(e, PDU_GET_RESPONSE, NULL));
		CHECK("request id", decode_integer(e, -1, &sid));

		si = find_sid_info(dest, sid);
		if (!si) {
			log_info("late reply, ignoring packet", "peer", peer, "sid", U(sid), NULL);
			return;
		}

		if (process_sid_info_response(si, e))
			free_sid_info(si);
		maybe_query_destination(dest);
		return;

	} else {
		unsigned msg_flags_len, username_len;
		unsigned usm;
		unsigned char *auth_param_ptr;
		unsigned auth_param_len = 0;
		unsigned char auth_param[EVP_MAX_MD_SIZE];
		unsigned char priv_param[8];
		struct snmpv3info v3, *siv3;
		unsigned char context_engine_id[V3O_ENGINE_ID_MAXLEN];

		memset(&v3, 0, sizeof(v3));

        CHECK("msgGlobalData sequence", decode_sequence(e, NULL));
		CHECK("msgID", decode_integer(e, -1, &mid));
		CHECK("msgMaxSize", decode_integer(e, -1, &v3.msg_max_size));
		CHECK("msgFlags", decode_octets(e, &v3.msg_flags, 1, &msg_flags_len));
		if (msg_flags_len != 1) {
			trace = "msgFlags not 1 byte in length";
			goto bad_snmp_packet;
		}
		CHECK("msgSecurityModel", decode_integer(e, -1, &usm));
		if (usm != 3) {
			trace = "msgSecurityModel not USM";
			goto bad_snmp_packet;
		}

		CHECK("sec-params-string", decode_composite(e, AT_STRING, NULL));
        CHECK("sec-params-sequence", decode_sequence(e, NULL));
		CHECK("engine-id", decode_octets(e, v3.engine_id, V3O_ENGINE_ID_MAXLEN, &v3.engine_id_len));
		CHECK("engine-boots", decode_integer(e, -1, &v3.engine_boots));
		CHECK("engine-time", decode_integer(e, -1, &v3.engine_time));
		CHECK("username", decode_string(e, (unsigned char *)v3.username, V3O_USERNAME_MAXSIZE, &username_len));

        trace = "decoding auth-param";
        if (decode_type_len(e, &t, &l) < 0)
          goto bad_snmp_packet;
        if (t != AT_STRING)
          goto bad_snmp_packet;
		auth_param_ptr = e->b;
		auth_param_len = l;  // validated below, once the configured protocol (siv3) is known
        e->b += l; e->len += l;
		CHECK("priv-param", decode_octets(e, priv_param, 8, &l));
		if ((v3.msg_flags & V3F_ENCRYPTED) && l != 8) {
			trace = "unexpected priv-param length for encrypted message";
			goto bad_snmp_packet;
		}

		si = find_sid_info(dest, mid);
		if (!si) {
			log_info("late reply, ignoring packet", "peer", peer, "mid", U(mid), NULL);
			trace = NULL;
			goto bad_snmp_packet;
		}

		// - ignore if no si->v3 setup
		if (si->cri->version != 3 || !si->cri->v3) {
			log_warn("no v3 info for reply, ignoring packet", "peer", peer, "mid", U(mid), NULL);
			trace = NULL;
			goto bad_snmp_packet;
		}
		siv3 = si->cri->v3;

        // - verify engine-id
        if (v3.engine_id_len != siv3->engine_id_len ||
            memcmp(v3.engine_id,
                   siv3->engine_id,
                   v3.engine_id_len) != 0)
		{
			char known[2*V3O_ENGINE_ID_MAXLEN+1] = "";
			char received[2*V3O_ENGINE_ID_MAXLEN+1] = "";
			int p, i;

			for (p = 0, i = 0; i < v3.engine_id_len; i++)
				p += snprintf(known+p, sizeof(known)-p, "%02x", siv3->engine_id[i]);
			for (p = 0, i = 0; i < v3.engine_id_len; i++)
				p += snprintf(received+p, sizeof(received)-p, "%02x", v3.engine_id[i]);
			log_warn("engine-id mismatch, ignoring packet", "peer", peer, "mid", U(mid),
					"known_engine_id", known, "recv_engine_id", received, NULL);
			trace = NULL;
			goto bad_snmp_packet;
        }

		// - verify username
		if (strcmp(siv3->username, v3.username) != 0) {
			log_warn("username mismatch, ignoring packet", "peer", peer, "mid", U(mid),
					"known_username", siv3->username, "username", v3.username, NULL);
			trace = NULL;
			goto bad_snmp_packet;
		}

		// - do auth check
		if ((v3.msg_flags & V3F_AUTHENTICATED)) {
			int maclen = v3_auth_maclen(siv3->auth_proto);
			if (maclen < 0) {
				trace = "unsupported auth protocol";
				goto bad_snmp_packet;
			}
			if (auth_param_len != (unsigned)maclen) {
				trace = "unexpected auth-param length for authenticated message";
				goto bad_snmp_packet;
			}
			memcpy(auth_param, auth_param_ptr, maclen);
			memset(auth_param_ptr, 0, maclen); // clear original HMAC location for auth calculations
    		if (hmac_message(siv3, auth_param_ptr, maclen, e->buf, e->max_len, auth_param_ptr) < 0) {
				memcpy(auth_param_ptr, auth_param, maclen);
				log_warn("authentication failed", "peer", peer, "mid", U(mid),
						"error", strerror(errno), NULL);
				log_debug("authentication failed", "peer", peer, "mid", U(mid),
						"packet", HEXBUF(e->buf, e->max_len), NULL);
				trace = NULL;
				goto bad_snmp_packet;
			}
			if (memcmp(auth_param_ptr, auth_param, maclen) != 0) {
				char auth_calc[2 * EVP_MAX_MD_SIZE + 1];

				snprintf(auth_calc, sizeof(auth_calc), "%s", HEXBUF(auth_param_ptr, maclen));
				memcpy(auth_param_ptr, auth_param, maclen);
				log_warn("authentication failed", "peer", peer, "mid", U(mid), NULL);
				log_debug("authentication failed", "peer", peer, "mid", U(mid),
						"auth_calc", auth_calc,
						"packet", HEXBUF(e->buf, e->max_len), NULL);
				trace = NULL;
				goto bad_snmp_packet;
			}
		}

		// - update engine-boots and engine-time
		siv3->engine_boots = v3.engine_boots;
		siv3->engine_time  = v3.engine_time;

		if ((v3.msg_flags & V3F_ENCRYPTED)) {
        	trace = "decoding encrypted-pdu";
        	if (decode_type_len(e, &t, &l) < 0)
          		goto bad_snmp_packet;
        	if (t != AT_STRING) goto bad_snmp_packet;
			// - decrypt
			if (decrypt_in_place(e->b, l, priv_param, siv3) < 0) {
				log_warn("cannot decrypt, ignoring packet", "peer", peer, "mid", U(mid), NULL);
				trace = NULL;
				goto bad_snmp_packet;
			}
		}

		// - parse decrypted/plaintext PDU
        CHECK("decrypted/plaintext PDU", decode_sequence(e, NULL));
		CHECK("context-engine-id", decode_octets(e, context_engine_id, V3O_ENGINE_ID_MAXLEN, &l));
		// - compare engine-id, must be same
        if (v3.engine_id_len != l || memcmp(v3.engine_id, context_engine_id, l) != 0) {
			char authoritative[2*V3O_ENGINE_ID_MAXLEN+1] = "";
			char context[2*V3O_ENGINE_ID_MAXLEN+1] = "";
			int p, i;

			for (p = 0, i = 0; i < l; i++)
				p += snprintf(authoritative+p, sizeof(authoritative)-p, "%02x", v3.engine_id[i]);
			for (p = 0, i = 0; i < l; i++)
				p += snprintf(context+p, sizeof(context)-p, "%02x", context_engine_id[i]);
			log_warn("authoritative/context engine-id mismatch, ignoring packet", "peer", peer,
					"mid", U(mid), "auth_engine_id", authoritative, "context_engine_id", context, NULL);
			trace = NULL;
			goto bad_snmp_packet;
        }
        trace = "decoding context-name (skip)";
        if (decode_type_len(e, &t, &l) < 0)
          goto bad_snmp_packet;
        if (t != AT_STRING)
          goto bad_snmp_packet;
        e->b += l;
        e->len += l;

		// - parse report/get-response PDU
		if (e->len + 1 > e->max_len) {
			CHECK("reply-pdu", -1);
		}
		t = e->b[0];
		if (t != PDU_REPORT && t != PDU_GET_RESPONSE) {
			log_warn("unsupported PDU type, ignoring packet", "peer", peer, "mid", U(mid),
					"pdu_type", HEX(t), NULL);
			trace = NULL;
			goto bad_snmp_packet;
		}

		CHECK("reply-pdu", decode_composite(e, t, NULL));
		CHECK("request-id", decode_integer(e, -1, &sid));
		//   - compare request-id, should be same as message-id (but well, not really)
		if (sid != mid) {
			// if our request HMAC is wrong, some implementations return 0x7fffffff
			// to be on the safe side, we generally ignore sid != mid situation
			if (sid != 0x7fffffff)
				log_warn("message-id does not match request-id", "peer", peer,
						"mid", U(mid), "sid", U(sid), NULL);
		}

		// - if it's a report, make sure re-sending is done ASAP and no timeout counter increases
		if (t == PDU_REPORT) {
			unsigned error_status, error_index;
			int oids_stop;
			struct ber oid, val;

			CHECK("error-status", decode_integer(e, -1, &error_status));
			if (error_status != 0) {
				log_warn("non-zero error-status", "peer", peer, "mid", U(mid),
						"error_status", I(error_status), NULL);
			}
			CHECK("error-index", decode_integer(e, -1, &error_index));
			if (error_index != 0) {
				log_warn("non-zero error-index", "peer", peer, "mid", U(mid),
						"error_index", I(error_index), NULL);
			}

			// - analyze varbinds and report
			CHECK("var-binds", decode_sequence(e, &oids_stop));
			while (inside_sequence(e, oids_stop)) {
				CHECK("varbind", decode_sequence(e, NULL));
				CHECK("oid", decode_oid(e, &oid));
				CHECK("value", decode_any(e, &val));

				if (oid_compare(&oid, &usmStatsNotInTimeWindows) == 0) {
					sid_stop_timing(si);
					si->retries_left++;  // a hack since resend() decrements this
					// XXX resend() increments snmp_retries counter(s), which is misleading in this case
					resend_query_with_new_sid(si);
					return;
				} else if (oid_compare(&oid, &usmStatsWrongDigests) == 0) {
					log_warn("report: bad digest, ignoring packet", "peer", peer, "mid", U(mid), NULL);
					trace = NULL;
					goto bad_snmp_packet;
				} else {
					log_warn("report", "peer", peer, "mid", U(mid), "oid", oid2str(oid), NULL);
					log_debug("report", "peer", peer, "mid", U(mid),
							"value", HEXBUF(val.buf, (size_t)val.len), NULL);
					trace = NULL;
					goto bad_snmp_packet;
				}
			}
		}

		if (t == PDU_GET_RESPONSE) {
			// normal processing
			if (process_sid_info_response(si, e))
				free_sid_info(si);
			maybe_query_destination(dest);
			return;
		}

		trace = "V3 so far so good";
		goto bad_snmp_packet;
    }
	#undef CHECK

	return;

bad_snmp_packet:
	PS.bad_snmp_responses++;
	if (trace)
		log_warn("bad SNMP packet, ignoring", "peer", peer, "trace", trace, NULL);
	maybe_query_destination(dest);
}

static void
snmp_receive(struct socket_info *snmp)
{
	struct sockaddr_in from;
	socklen_t len;
	char buf[65000];
	int n;

	while (1) {
		len = sizeof(from);
		if ( (n = recvfrom(snmp->fd, buf, 65000, 0, (struct sockaddr *)&from, &len)) < 0) {
			if (errno == EAGAIN)
				return;
			croak(1, "snmp_receive: recvfrom");
		}
		snmp_process_datagram(snmp, &from, buf, n);
	}
}

void
create_snmp_socket(void)
{
	int fd;
	int n;
	int flags;

	if (snmp)
		croakx(1, "create_snmp_socket: socket already exists");

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		croak(1, "create_snmp_socket: socket");

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		croak(1, "create_snmp_socket: fcntl(getfl)");
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0)
		croak(1, "create_snmp_socket: fcntl(setfl)");

	/* try a very large receive buffer size */
	n = 100 * 1024 * 1024;
	while (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n)) < 0)
		n /= 2;
	PS.udp_receive_buffer_size = n;

	/* additionally, try a very large send buffer size :) */
	n = 100 * 1024 * 1024;
	while (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, sizeof(n)) < 0)
		n /= 2;
	PS.udp_send_buffer_size = n;

	snmp = new_socket_info(fd);
	on_read(snmp, snmp_receive);
}

void snmp_send(struct destination *dest, struct ber *packet)
{
	ssize_t n;

	destination_start_timing(dest);

	dest->packets_on_the_wire++;
	PS.packets_on_the_wire++;
	n = sendto(snmp->fd, packet->buf, packet->len, 0,
			   (struct sockaddr *)&dest->dest_addr,
			   sizeof(dest->dest_addr));
	if (n < 0) {
		if (errno == EAGAIN) {
			PS.udp_send_buffer_overflow++;
			return;
		}
		croak(1, "snmp_send: sendto");
	}
	if (n != packet->len)
		croakx(1, "snmp_send: short send");

	dest->octets_sent += packet->len;
	PS.octets_sent += packet->len;
}

