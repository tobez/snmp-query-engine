/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2014, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

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
	char log[256];

	snprintf(log, sizeof(log), "%s %s:%d", timestring(), inet_ntoa(from->sin_addr), ntohs(from->sin_port));

	PS.octets_received += n;
	dest = find_destination(&from->sin_addr, ntohs(from->sin_port));
	if (!dest) {
		fprintf(stderr, "%s: destination is not known, ignoring packet\n", log);
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

		snprintf(log, sizeof(log), "%s %s:%d[%u]", timestring(), inet_ntoa(from->sin_addr), ntohs(from->sin_port), sid);

		si = find_sid_info(dest, sid);
		if (!si) {
			fprintf(stderr, "%s: unable to find sid_info, ignoring packet\n", log);
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
		unsigned char auth_param[12];
		unsigned char priv_param[8];
		struct snmpv3info v3, *siv3;
		unsigned char context_engine_id[V3O_ENGINE_ID_MAXLEN];

		memset(&v3, 0, sizeof(v3));

        CHECK("msgGlobalData sequence", decode_sequence(e, NULL));
		CHECK("msgID", decode_integer(e, -1, &mid));
		snprintf(log, sizeof(log), "%s %s:%d[%u]", timestring(), inet_ntoa(from->sin_addr), ntohs(from->sin_port), mid);
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
        e->b += l; e->len += l;
		if ((v3.msg_flags & V3F_AUTHENTICATED)) {
			if (l != 12) {
				trace = "unexpected auth-param length for authenticated message";
				goto bad_snmp_packet;
			}
			memcpy(auth_param, auth_param_ptr, 12);
			memset(auth_param_ptr, 0, 12); // clear original HMAC location for auth calculations
		}
		CHECK("priv-param", decode_octets(e, priv_param, 8, &l));
		if ((v3.msg_flags & V3F_ENCRYPTED) && l != 8) {
			trace = "unexpected priv-param length for encrypted message";
			goto bad_snmp_packet;
		}

		si = find_sid_info(dest, mid);
		if (!mid) {
			fprintf(stderr, "%s: unable to find sid_info, ignoring packet\n", log);
			trace = NULL;
			goto bad_snmp_packet;
		}

		// - ignore if no si->v3 setup
		if (si->cri->version != 3 || !si->cri->v3) {
			fprintf(stderr, "%s: si->cri is not a V3, or no V3 info found, ignoring packet\n", log);
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
			fprintf(stderr, "%s: known engine-id ", log);
			for (int i = 0; i < v3.engine_id_len; i++) {
  				fprintf(stderr, "%02x", siv3->engine_id[i]);
			}
			fprintf(stderr, " does not match received engine-id ");
			for (int i = 0; i < v3.engine_id_len; i++) {
  				fprintf(stderr, "%02x", v3.engine_id[i]);
			}
			fprintf(stderr, ", ignoring packet\n");
			trace = NULL;
			goto bad_snmp_packet;
        }

		// - verify username
		if (strcmp(siv3->username, v3.username) != 0) {
			fprintf(stderr, "%s: known username \"%s\" does not match "
					"received username \"%s\", ignoring packet\n",
					log, siv3->username, v3.username);
			trace = NULL;
			goto bad_snmp_packet;
		}

		// - do auth check
		if ((v3.msg_flags & V3F_AUTHENTICATED)) {
    		if (hmac_message(siv3, auth_param_ptr, 12, e->buf, e->max_len, auth_param_ptr) < 0) {
				memcpy(auth_param_ptr, auth_param, 12);
				fprintf(stderr, "%s: authentication failed: %s, prepare for packet dump:\n",
						log, strerror(errno));
				dump_buf(stderr, e->buf, e->max_len);
				trace = NULL;
				goto bad_snmp_packet;
			}
			if (memcmp(auth_param_ptr, auth_param, 12) != 0) {
				fprintf(stderr, "%s: authentication failed, calculated digest:\n", log);
				dump_buf(stderr, auth_param_ptr, 12);
				memcpy(auth_param_ptr, auth_param, 12);
				fprintf(stderr, "prepare for packet dump:\n");
				dump_buf(stderr, e->buf, e->max_len);
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
				fprintf(stderr, "%s: cannot decrypt, ignoring packet\n", log);
				trace = NULL;
				goto bad_snmp_packet;
			}
		}

		// - parse decrypted/plaintext PDU
        CHECK("decrypted/plaintext PDU", decode_sequence(e, NULL));
		CHECK("context-engine-id", decode_octets(e, context_engine_id, V3O_ENGINE_ID_MAXLEN, &l));
		// - compare engine-id, must be same
        if (v3.engine_id_len != l || memcmp(v3.engine_id, context_engine_id, l) != 0) {
			fprintf(stderr, "%s: authoritative-engine-id ", log);
			for (int i = 0; i < l; i++) {
  				fprintf(stderr, "%02x", v3.engine_id[i]);
			}
			fprintf(stderr, " does not match context-engine-id ");
			for (int i = 0; i < l; i++) {
  				fprintf(stderr, "%02x", context_engine_id[i]);
			}
			fprintf(stderr, ", ignoring packet\n");
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
			fprintf(stderr, "%s: unsupported PDU type %x, ignoring packet\n", log, t);
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
				fprintf(stderr, "%s: warning: message-id %u does not match request-id %u\n",
						log, mid, sid);
		}

		// - if it's a report, make sure re-sending is done ASAP and no timeout counter increases
		if (t == PDU_REPORT) {
			unsigned error_status, error_index;
			int oids_stop;
			struct ber oid, val;

			CHECK("error-status", decode_integer(e, -1, &error_status));
			if (error_status != 0) {
				fprintf(stderr, "%s: warning: non-zero error-status (%d)\n", log, error_status);
			}
			CHECK("error-index", decode_integer(e, -1, &error_index));
			if (error_index != 0) {
				fprintf(stderr, "%s: warning: non-zero error-index (%d)\n", log, error_index);
			}

			// - analyze varbinds and report
			CHECK("var-binds", decode_sequence(e, &oids_stop));
			while (inside_sequence(e, oids_stop)) {
				CHECK("varbind", decode_sequence(e, NULL));
				CHECK("oid", decode_oid(e, &oid));
				CHECK("value", decode_any(e, &val));

				if (oid_compare(&oid, &usmStatsNotInTimeWindows) == 0) {
					fprintf(stderr, "%s: report: our request not in time window, need to resend request\n", log);
					sid_stop_timing(si);
					si->retries_left++;  // a hack since resend() decrements this
					// XXX resend() increments snmp_retries counter(s), which is misleading in this case
					resend_query_with_new_sid(si);
					return;
				} else if (oid_compare(&oid, &usmStatsWrongDigests) == 0) {
					fprintf(stderr, "%s: report: our request had bad digest, ignoring packet\n", log);
					trace = NULL;
					goto bad_snmp_packet;
				} else {
					fprintf(stderr, "%s: report: %s: ", log, oid2str(oid));
					ber_dump(stderr, &val);
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
		fprintf(stderr, "%s: bad SNMP packet, ignoring: %s\n", log, trace);
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
	destination_start_timing(dest);

	dest->packets_on_the_wire++;
	PS.packets_on_the_wire++;
//fprintf(stderr, "%s: snmp_send->(%d)\n", inet_ntoa(dest->ip), dest->packets_on_the_wire);
	if (sendto(snmp->fd, packet->buf, packet->len, 0,
			   (struct sockaddr *)&dest->dest_addr,
			   sizeof(dest->dest_addr))
		!= packet->len)
	{
		if (errno == EAGAIN) {
			PS.udp_send_buffer_overflow++;
			return;
		}
		croak(1, "snmp_send: sendto");
	}
//fprintf(stderr, "UDP datagram of %d bytes sent to %s:%d\n", packet->len, inet_ntoa(dest->dest_addr.sin_addr), ntohs(dest->dest_addr.sin_port));
//dump_buf(stderr, packet->buf, packet->len);

	dest->octets_sent += packet->len;
	PS.octets_sent += packet->len;
}

