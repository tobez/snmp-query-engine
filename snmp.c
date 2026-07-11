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

/* Checks (on a private copy of the parse state) whether an unencrypted reply,
 * positioned at the scoped PDU, is a REPORT carrying the given usmStats oid. */
static int
report_carries_usm_stat(struct ber e, struct ber *stat_oid)
{
	unsigned char t;
	unsigned char context_engine_id[V3O_ENGINE_ID_MAXLEN];
	unsigned l, dummy;
	int oids_stop;
	struct ber oid, val;

	if (decode_sequence(&e, NULL) < 0)                                      return 0;
	if (decode_octets(&e, context_engine_id, V3O_ENGINE_ID_MAXLEN, &l) < 0) return 0;
	if (decode_type_len(&e, &t, &l) < 0)                                    return 0;
	if (t != AT_STRING)                                                     return 0;
	e.b += l;   /* skip context-name */
	e.len += l;
	if (e.len + 1 > e.max_len)                                              return 0;
	if (e.b[0] != PDU_REPORT)                                               return 0;
	if (decode_composite(&e, PDU_REPORT, NULL) < 0)                         return 0;
	if (decode_integer(&e, -1, &dummy) < 0)                                 return 0; /* request-id */
	if (decode_integer(&e, -1, &dummy) < 0)                                 return 0; /* error-status */
	if (decode_integer(&e, -1, &dummy) < 0)                                 return 0; /* error-index */
	if (decode_sequence(&e, &oids_stop) < 0)                                return 0;
	while (inside_sequence(&e, oids_stop)) {
		if (decode_sequence(&e, NULL) < 0)                                  return 0;
		if (decode_oid(&e, &oid) < 0)                                       return 0;
		if (decode_any(&e, &val) < 0)                                       return 0;
		if (oid_compare(&oid, stat_oid) == 0)                               return 1;
	}
	return 0;
}

/* Handles the REPORT answering an engine id discovery probe: adopts the
 * agent's engine id, localizes the stored passwords against it, and releases
 * the queries held during discovery.  Returns 1 when the packet was fully
 * handled, 0 when the caller should ignore it via the bad-packet path. */
static int
adopt_discovered_engine_id(struct sid_info *si, struct snmpv3info *pkt_v3, struct ber *e,
                           const char *peer, struct destination *dest)
{
	struct client_requests_info *cri = si->cri;
	struct snmpv3info *siv3 = cri->v3;
	char hex_eid[2*V3O_ENGINE_ID_MAXLEN+1] = "";
	char *err;
	int p, i;

	if (siv3->engine_state != V3_ENGINE_DISCOVERY || siv3->probe_sid != si->sid) {
		if (destination_log_allow(dest, LTC_REPORT))
			log_info("reply to a stale discovery probe, ignoring packet",
					"peer", peer, "mid", U(si->sid), NULL);
		return 0;
	}
	if ((pkt_v3->msg_flags & V3F_ENCRYPTED) ||
	    !report_carries_usm_stat(*e, &usmStatsUnknownEngineIDs))
	{
		if (destination_log_allow(dest, LTC_REPORT))
			log_warn("unexpected reply to discovery probe, ignoring packet",
					"peer", peer, "mid", U(si->sid), NULL);
		return 0;
	}

	memcpy(siv3->engine_id, pkt_v3->engine_id, pkt_v3->engine_id_len);
	siv3->engine_id_len = pkt_v3->engine_id_len;
	siv3->engine_boots  = pkt_v3->engine_boots;
	siv3->engine_time   = pkt_v3->engine_time;
	for (p = 0, i = 0; i < siv3->engine_id_len; i++)
		p += snprintf(hex_eid+p, sizeof(hex_eid)-p, "%02x", siv3->engine_id[i]);

	if (siv3->authpass[0] &&
	    !password_to_kul(siv3->auth_proto, siv3->authpass, strlen(siv3->authpass),
	                     siv3->engine_id, siv3->engine_id_len,
	                     siv3->authkul, V3O_AUTHKUL_MAXSIZE, &siv3->authkul_len, &err))
		goto kul_error;
	if (siv3->privpass[0]) {
		if (!password_to_kul(siv3->auth_proto, siv3->privpass, strlen(siv3->privpass),
		                     siv3->engine_id, siv3->engine_id_len,
		                     siv3->privkul, V3O_PRIVKUL_MAXSIZE, &siv3->privkul_len, &err))
			goto kul_error;
		if (!expand_kul(siv3->auth_proto, siv3->priv_proto,
		                siv3->privkul, siv3->privkul_len,
		                siv3->engine_id, siv3->engine_id_len,
		                siv3->x_privkul, V3O_PRIVKUL_MAXSIZE, &siv3->x_privkul_len, &err))
			goto kul_error;
	}

	siv3->engine_state = V3_ENGINE_KNOWN;
	siv3->probe_sid = 0;
	PS.v3_engineid_discoveries++;
	log_info("discovered engine id", "peer", peer, "engine_id", hex_eid, NULL);
	free_sid_info(si);
	maybe_query_destination(dest);
	return 1;

kul_error:
	{
		struct ber errval = ber_string_error("kul-calculation-error");

		errval.len = errval.max_len; /* fail_queued_oids ber_dup()s the encoded
		                               * length, not the rewound decode position */
		log_error("kul calculation error after engine id discovery",
				"peer", peer, "engine_id", hex_eid, "error", err, NULL);
		siv3->engine_id_len = 0;
		siv3->probe_sid = 0;
		fail_queued_oids(cri, &errval);
		free(errval.buf);
		free_sid_info(si);
		maybe_query_destination(dest);
	}
	return 1;
}

/* Fails all of a sid's oids with ["engine-id-mismatch: <hex>"] carrying the
 * engine id the peer claimed.  Only the one request fails; the cri keeps its
 * configuration, so a corrected setopt recovers instantly. */
static void
fail_sid_engine_id_mismatch(struct sid_info *si, struct snmpv3info *pkt_v3,
                            const char *peer, struct destination *dest)
{
	char known[2*V3O_ENGINE_ID_MAXLEN+1] = "";
	char received[2*V3O_ENGINE_ID_MAXLEN+1] = "";
	char errstr[2*V3O_ENGINE_ID_MAXLEN+32];
	struct snmpv3info *siv3 = si->cri->v3;
	struct ber errval;
	int p, i;

	for (p = 0, i = 0; i < siv3->engine_id_len; i++)
		p += snprintf(known+p, sizeof(known)-p, "%02x", siv3->engine_id[i]);
	for (p = 0, i = 0; i < pkt_v3->engine_id_len; i++)
		p += snprintf(received+p, sizeof(received)-p, "%02x", pkt_v3->engine_id[i]);
	snprintf(errstr, sizeof(errstr), "engine-id-mismatch: %s", received);

	PS.v3_engineid_mismatches++;
	if (destination_log_allow(dest, LTC_ENGINE_ID_MISMATCH))
		log_warn("engine-id mismatch, failing request", "peer", peer, "mid", U(si->sid),
				"known_engine_id", known, "recv_engine_id", received, NULL);

	errval = ber_string_error(errstr);
	errval.len = errval.max_len; /* oid_done/all_oids_done ber_dup() the encoded
	                               * length, not the rewound decode position */
	if (si->table_oid) {
		oid_done(si, si->table_oid, &errval, RT_GETTABLE, 0);
		si->table_oid = NULL;
	} else {
		all_oids_done(si, &errval);
	}
	free(errval.buf);
	free_sid_info(si);
	maybe_query_destination(dest);
}

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
	const char *peer = peer_str(from);

	PS.octets_received += n;
	dest = find_destination(&from->sin_addr, ntohs(from->sin_port));
	if (!dest) {
		if (log_throttle_allow_standalone(LTC_UNKNOWN_DESTINATION))
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
			if (destination_log_allow(dest, LTC_LATE_REPLY))
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
			if (destination_log_allow(dest, LTC_LATE_REPLY))
				log_info("late reply, ignoring packet", "peer", peer, "mid", U(mid), NULL);
			trace = NULL;
			goto bad_snmp_packet;
		}

		// - ignore if no si->v3 setup
		if (si->cri->version != 3 || !si->cri->v3) {
			if (destination_log_allow(dest, LTC_NO_V3_INFO))
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

			if (si->probe) {
				if (adopt_discovered_engine_id(si, &v3, e, peer, dest))
					return;
				trace = NULL;
				goto bad_snmp_packet;
			}

			if (!(v3.msg_flags & V3F_ENCRYPTED) &&
			    report_carries_usm_stat(*e, &usmStatsUnknownEngineIDs))
			{
				fail_sid_engine_id_mismatch(si, &v3, peer, dest);
				return;
			}

			for (p = 0, i = 0; i < v3.engine_id_len; i++)
				p += snprintf(known+p, sizeof(known)-p, "%02x", siv3->engine_id[i]);
			for (p = 0, i = 0; i < v3.engine_id_len; i++)
				p += snprintf(received+p, sizeof(received)-p, "%02x", v3.engine_id[i]);
			if (destination_log_allow(dest, LTC_ENGINE_ID_MISMATCH))
				log_warn("engine-id mismatch, ignoring packet", "peer", peer, "mid", U(mid),
						"known_engine_id", known, "recv_engine_id", received, NULL);
			trace = NULL;
			goto bad_snmp_packet;
        }

		// - verify username
		if (strcmp(siv3->username, v3.username) != 0) {
			if (destination_log_allow(dest, LTC_USERNAME_MISMATCH))
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
				if (destination_log_allow(dest, LTC_AUTH_FAILED))
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
				if (destination_log_allow(dest, LTC_AUTH_FAILED))
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
				if (destination_log_allow(dest, LTC_CANNOT_DECRYPT))
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
			if (destination_log_allow(dest, LTC_AUTHCTX_ENGINE_MISMATCH))
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
			if (destination_log_allow(dest, LTC_UNSUPPORTED_PDU))
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
			if (sid != 0x7fffffff && destination_log_allow(dest, LTC_MSGID_MISMATCH))
				log_warn("message-id does not match request-id", "peer", peer,
						"mid", U(mid), "sid", U(sid), NULL);
		}

		// - if it's a report, make sure re-sending is done ASAP and no timeout counter increases
		if (t == PDU_REPORT) {
			unsigned error_status, error_index;
			int oids_stop;
			struct ber oid, val;

			CHECK("error-status", decode_integer(e, -1, &error_status));
			if (error_status != 0 && destination_log_allow(dest, LTC_ERROR_STATUS))
				log_warn("non-zero error-status", "peer", peer, "mid", U(mid),
						"error_status", I(error_status), NULL);
			CHECK("error-index", decode_integer(e, -1, &error_index));
			if (error_index != 0 && destination_log_allow(dest, LTC_ERROR_INDEX))
				log_warn("non-zero error-index", "peer", peer, "mid", U(mid),
						"error_index", I(error_index), NULL);

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
					if (destination_log_allow(dest, LTC_REPORT_BAD_DIGEST))
						log_warn("report: bad digest, ignoring packet", "peer", peer, "mid", U(mid), NULL);
					trace = NULL;
					goto bad_snmp_packet;
				} else {
					if (destination_log_allow(dest, LTC_REPORT))
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
	if (trace && destination_log_allow(dest, LTC_BAD_PACKET))
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
			if (log_throttle_allow_standalone(LTC_SEND_BUFFER_OVERFLOW))
				log_warn("udp send buffer overflow, dropping datagram",
					"peer", peer_str(&dest->dest_addr), NULL);
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

