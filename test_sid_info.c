/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2025, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
/* ABOUTME: Tests that a table walk terminates when a device returns a
 * ABOUTME: non-increasing (repeated or smaller) OID, per PR #8. */
#include "sqe.h"

static int n_tests = 0;
static int success = 0;

static void
check(const char *name, int ok)
{
	n_tests++;
	if (ok) {
		success++;
	} else {
		fprintf(stderr, "test %d, %s: FAILED\n", n_tests, name);
	}
}

/* Encode an OID string into a freshly allocated BER, shaped like the OID
 * bers produced by decode_oid() (buf points at the type byte, max_len
 * covers the whole TLV). */
static struct ber
make_oid(const char *s)
{
	unsigned char tmp[256];
	struct ber e = ber_init(tmp, sizeof tmp);

	if (encode_string_oid(s, -1, &e) < 0)
		croak(2, "make_oid: encode_string_oid(%s)", s);
	return ber_dup(&e);
}

/* Build the tail of a GET-RESPONSE that process_sid_info_response() expects:
 * error-status, error-index, then a varbind list holding a single
 * { OID, INTEGER } binding for the given table entry OID. */
static struct ber
make_response(const char *entry_oid)
{
	static unsigned char buf[512];
	struct ber e = ber_init(buf, sizeof buf);
	unsigned char *varbind_list, *varbind;

	bzero(buf, sizeof buf);
	if (encode_integer(0, &e, 0) < 0)      /* error-status */
		croak(2, "make_response: error-status");
	if (encode_integer(0, &e, 0) < 0)      /* error-index */
		croak(2, "make_response: error-index");

	varbind_list = e.b;
	if (encode_type_len(AT_SEQUENCE, 0, &e) < 0)
		croak(2, "make_response: varbind list");
	varbind = e.b;
	if (encode_type_len(AT_SEQUENCE, 0, &e) < 0)
		croak(2, "make_response: varbind");
	if (encode_string_oid(entry_oid, -1, &e) < 0)
		croak(2, "make_response: oid");
	if (encode_integer(42, &e, 0) < 0)     /* value */
		croak(2, "make_response: value");
	encode_store_length(&e, varbind);
	encode_store_length(&e, varbind_list);

	return ber_rewind(e);
}

/* Drive one response OID through a table walk whose last known entry is
 * last_known, and report how much oids_non_increasing moved. */
static void
run_case(const char *name, const char *table_base, const char *last_known,
         const char *response_entry, int64_t expected_delta)
{
	struct destination dest;
	struct socket_info sock;
	struct client_requests_info cri;
	struct cid_info *ci;
	struct oid_info last_oi;
	struct oid_info *table_oid;
	struct sid_info si;
	struct ber resp;
	int64_t before, delta;
	int rc;
	unsigned cid = 100;

	bzero(&dest, sizeof dest);
	dest.max_repetitions = 10;

	bzero(&sock, sizeof sock);
	TAILQ_INIT(&sock.send_bufs);

	bzero(&cri, sizeof cri);
	cri.dest = &dest;
	cri.si = &sock;
	cri.fd = 7;
	cri.version = 2;
	TAILQ_INIT(&cri.oids_to_query);
	TAILQ_INIT(&cri.sid_infos);

	ci = get_cid_info(&cri, cid);
	/* Pretend a second OID for this client request is still outstanding so
	 * the end-of-walk cid_reply() (which needs the event loop) never fires;
	 * we assert on the non-increasing counter, not on the client reply. */
	ci->n_oids = 2;
	ci->n_oids_being_queried = 1;
	ci->n_oids_done = 0;

	bzero(&last_oi, sizeof last_oi);
	last_oi.oid = make_oid(last_known);

	table_oid = malloc(sizeof *table_oid);
	if (!table_oid)
		croak(2, "run_case: malloc(table_oid)");
	bzero(table_oid, sizeof *table_oid);
	table_oid->cid = cid;
	table_oid->fd = cri.fd;
	table_oid->oid = make_oid(table_base);
	table_oid->last_known_table_entry = &last_oi;
	table_oid->max_repetitions = 10;

	bzero(&si, sizeof si);
	si.cri = &cri;
	si.sid = 55;
	si.version = 2;
	si.table_oid = table_oid;
	TAILQ_INIT(&si.oids_being_queried);

	resp = make_response(response_entry);

	before = PS.oids_non_increasing;
	rc = process_sid_info_response(&si, &resp);
	delta = PS.oids_non_increasing - before;

	check(name, rc == 1 && delta == expected_delta);
}

int
main(void)
{
	const char *base = "1.3.6.1.2.1.2.2.1.2";

	/* A device that repeats the same OID must be treated as non-increasing
	 * so the walk terminates instead of looping forever. */
	run_case("repeated oid terminates walk",
	         base, "1.3.6.1.2.1.2.2.1.2.1", "1.3.6.1.2.1.2.2.1.2.1", 1);

	/* A strictly larger OID is a normal table advance, not non-increasing. */
	run_case("increasing oid continues walk",
	         base, "1.3.6.1.2.1.2.2.1.2.1", "1.3.6.1.2.1.2.2.1.2.2", 0);

	/* A smaller OID is non-increasing, terminating the walk. */
	run_case("smaller oid terminates walk",
	         base, "1.3.6.1.2.1.2.2.1.2.2", "1.3.6.1.2.1.2.2.1.2.1", 1);

	fprintf(stderr, "%d of %d tests passed succesfully\n", success, n_tests);
	return success != n_tests;
}
