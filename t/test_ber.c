/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2013, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"
#include "tap.h"

int
test_encode_string_oid(char *oid, int oid_len, const char *res, int len)
{
	char *buf = malloc(len + 20);
	struct ber e = ber_init(buf, len + 20);
	char out_buf[4096];
	int oid_len2;

	buf[len] = '\x55';
	if (oid_len >= 0) {
		oid[oid_len] = '\xAA';
		oid_len2 = oid_len;
	} else {
		oid_len2 = strlen(oid);
	}
	if (encode_string_oid(oid, oid_len, &e) < 0) {
		tap_diag("encode_string_oid: unexpected failure, oid %s", oid);
		free(buf);
		return 0;
	}
	if (oid_len >= 0 && oid[oid_len] != '\xAA') {
		tap_diag("encode_string_oid: corrupted OID string");
		free(buf);
		return 0;
	}
	if (e.len != len) {
		tap_diag("encode_string_oid: unexpected length (%d != %d), oid %s", e.len, len, oid);
		free(buf);
		return 0;
	}
	if (buf[len] != '\x55') {
		tap_diag("encode_string_oid: buffer corruped, oid %s", oid);
		free(buf);
		return 0;
	}
	if (!decode_string_oid((unsigned char *)buf, len, out_buf, 4096)) {
		tap_diag("decode_string_oid: cannot decode encoded oid %s", oid);
		free(buf);
		return 0;
	}
	// fprintf(stderr, "ORIGINAL: %s\nDECODED : %s\n", oid, out_buf);
	if (strlen(out_buf) != (*oid == '.' ? oid_len2-1 : oid_len2)) {
		tap_diag("decode_string_oid: decoded oid len != encoded oid len, %s", oid);
		free(buf);
		return 0;
	}
	if (strncmp(*oid == '.' ? oid+1 : oid, out_buf, *oid == '.' ? oid_len2-1 : oid_len2) != 0) {
		tap_diag("decode_string_oid: decoded oid != encoded oid %s", oid);
		free(buf);
		return 0;
	}
	if (memcmp(buf, res, len) != 0) {
		tap_diag("encode_string_oid: unexpected buffer content, oid %s", oid);
		free(buf);
		return 0;
	}
	e = ber_init(buf, len);
	if (encode_string_oid(oid, oid_len, &e) < 0) {
		tap_diag("encode_string_oid: unexpected failure with just enough buffer space, oid %s", oid);
		free(buf);
		return 0;
	}
	e = ber_init(buf, len-1);
	if (encode_string_oid(oid, oid_len, &e) == 0) {
		tap_diag("encode_string_oid: unexpected success with slightly not enough buffer space, oid %s", oid);
		free(buf);
		return 0;
	}
	free(buf);
	return 1;
}

int
test_encode_string(const char *test_string, int real_string_offset)
{
	int len = strlen(test_string);
	const char *s = test_string + real_string_offset;
	char *buf = malloc(len + 20);
	struct ber e = ber_init(buf, len + 20);

	buf[len] = '\x55';
	if (encode_string(s, &e) < 0) {
		tap_diag("encode_string: unexpected failure, string %s", s);
		free(buf);
		return 0;
	}
	if (e.len != len) {
		tap_diag("encode_string: unexpected length (%d != %d), string %s", e.len, len, s);
		free(buf);
		return 0;
	}
	if (buf[len] != '\x55') {
		tap_diag("encode_string: buffer corruped, string %s", s);
		free(buf);
		return 0;
	}
	if (memcmp(buf, test_string, len) != 0) {
		tap_diag("encode_string: unexpected buffer content, string %s", s);
		free(buf);
		return 0;
	}
	e = ber_init(buf, len);
	if (encode_string(s, &e) < 0) {
		tap_diag("encode_string: unexpected failure with just enough buffer space, string %s", s);
		free(buf);
		return 0;
	}
	e = ber_init(buf, len-1);
	if (encode_string(s, &e) == 0) {
		tap_diag("encode_string: unexpected success with slightly not enough buffer space, string %s", s);
		free(buf);
		return 0;
	}
	free(buf);
	return 1;
}

int
test_oid_compare(const char *o1, const char *o2, int expected)
{
	char buf1[4096];
	char buf2[4096];
	struct ber oid1 = ber_init(buf1, 4096);
	struct ber oid2 = ber_init(buf2, 4096);
	int got;

	if (encode_string_oid(o1, -1, &oid1) < 0) {
		tap_diag("encode_string_oid: unexpected failure, oid %s", o1);
		return 0;
	}
	if (encode_string_oid(o2, -1, &oid2) < 0) {
		tap_diag("encode_string_oid: unexpected failure, oid %s", o2);
		return 0;
	}
	if ((got = oid_compare(&oid1, &oid2)) != expected) {
		tap_diag("oid_compare(\"%s\",\"%s\"): expected %d, got %d", o1, o2, expected, got);
		return 0;
	}
	return 1;
}

int
test_encode_integer(unsigned value, int force_size, const char *res, int len)
{
	unsigned char buf[16];
	struct ber e = ber_init(buf, 16);
	unsigned decoded;

	if (encode_integer(value, &e, force_size) < 0) {
		tap_diag("encode_integer(%u,%d): unexpected failure", value, force_size);
		return 0;
	}
	if (e.len != len) {
		tap_diag("encode_integer(%u,%d): unexpected length (%d != %d)", value, force_size, e.len, len);
		return 0;
	}
	if (memcmp(buf, res, len) != 0) {
		tap_diag("encode_integer(%u,%d): unexpected buffer content", value, force_size);
		return 0;
	}
	e = ber_init(buf, len);
	if (decode_integer(&e, -1, &decoded) < 0) {
		tap_diag("encode_integer(%u,%d): cannot decode encoded integer", value, force_size);
		return 0;
	}
	if (decoded != value) {
		tap_diag("encode_integer(%u,%d): decode round-trip gave %u", value, force_size, decoded);
		return 0;
	}
	return 1;
}

int
test_next_sid_from(unsigned cur, unsigned expected)
{
	unsigned got;

	if ((got = next_sid_from(cur)) != expected) {
		tap_diag("next_sid_from(%#x): expected %#x, got %#x", cur, expected, got);
		return 0;
	}
	return 1;
}

static int
buf_find(const unsigned char *hay, int hay_len, const char *needle, int needle_len)
{
	int i;
	for (i = 0; i + needle_len <= hay_len; i++)
		if (memcmp(hay + i, (const unsigned char *)needle, needle_len) == 0)
			return 1;
	return 0;
}

int
test_v3_header_encoding(void)
{
	struct packet_builder pb;
	struct snmpv3info v3;
	struct ber *e;

	memset(&v3, 0, sizeof(v3));
	memcpy(v3.engine_id, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 12);
	v3.engine_id_len = 12;
	strcpy(v3.username, "testuser");
	v3.auth_proto = V3O_AUTH_PROTO_SHA1;
	v3.priv_proto = V3O_PRIV_PROTO_AES128;
	v3.msg_max_size = 50000;
	v3.engine_boots = 200;
	v3.engine_time = 40000;

	if (start_snmp_packet(&pb, 3, 0x01020304, &v3, NULL) < 0) {
		tap_diag("v3 header: start_snmp_packet unexpected failure");
		return 0;
	}
	e = &pb.e;
	if (!buf_find(e->buf, e->len, "\x02\x03\x00\xc3\x50", 5)) {
		tap_diag("v3 header: msgMaxSize 50000 not encoded as 02 03 00 c3 50");
		free(e->buf);
		return 0;
	}
	if (!buf_find(e->buf, e->len, "\x02\x02\x00\xc8", 4)) {
		tap_diag("v3 header: engine boots 200 not encoded as 02 02 00 c8");
		free(e->buf);
		return 0;
	}
	if (!buf_find(e->buf, e->len, "\x02\x03\x00\x9c\x40", 5)) {
		tap_diag("v3 header: engine time 40000 not encoded as 02 03 00 9c 40");
		free(e->buf);
		return 0;
	}
	if (memcmp(e->buf + pb.pi.sid_offset, "\x01\x02\x03\x04", 4) != 0) {
		tap_diag("v3 header: sid_offset does not point at msgID bytes");
		free(e->buf);
		return 0;
	}
	free(e->buf);
	return 1;
}

int
test_v2c_getbulk_packet(int max_repetitions, const char *mrep_tlv)
{
	struct packet_builder pb;
	struct packet_info pi;
	struct ber packet;
	char oidbuf[64];
	struct ber oid = ber_init(oidbuf, 64);

	if (encode_string_oid("1.3.6.1.2.1.1.9.1.2", -1, &oid) < 0) {
		tap_diag("getbulk: cannot encode test oid");
		return 0;
	}
	if (start_snmp_packet(&pb, 1, 0x01020304, NULL, "public") < 0) {
		tap_diag("getbulk: start_snmp_packet unexpected failure");
		return 0;
	}
	if (add_encoded_oid_to_snmp_packet(&pb, &oid) < 0) {
		tap_diag("getbulk: add_encoded_oid_to_snmp_packet unexpected failure");
		return 0;
	}
	if (finalize_snmp_packet(&pb, &packet, NULL, &pi, PDU_GET_BULK_REQUEST, max_repetitions) < 0) {
		tap_diag("getbulk: finalize_snmp_packet unexpected failure");
		return 0;
	}
	if (!buf_find(packet.buf, packet.len, mrep_tlv, 3)) {
		tap_diag("getbulk(%d): expected max-repetitions TLV not found", max_repetitions);
		free(packet.buf);
		return 0;
	}
	if (memcmp(packet.buf + pi.sid_offset, "\x01\x02\x03\x04", 4) != 0) {
		tap_diag("getbulk: sid_offset does not point at request-id bytes");
		free(packet.buf);
		return 0;
	}
	free(packet.buf);
	return 1;
}

int
main(void)
{
	char oid[256];
	struct in_addr ip;
	struct ber bt;
	unsigned char buf[80];

	bt.buf = buf;
	bt.b = buf;
	bt.len = 0;
	bt.max_len = 80;
	strcpy((char *)buf, "\x40\x04\xff\xff\xff\xfc");
	ok(decode_ipv4_address(&bt, -1, &ip) == 0 && strcmp(inet_ntoa(ip), "255.255.255.252") == 0,
	    "decode_ipv4_address 255.255.255.252");

	strcpy(oid, "1.3.6.1.2.1.2.2.1.2.1001");
	ok(test_encode_string_oid(oid, 24, "\x06\x0b\x2b\x06\x01\x02\x01\x02\x02\x01\x02\x87\x69", 13),
	    "encode_string_oid 1.3.6.1.2.1.2.2.1.2.1001");
	strcpy(oid, ".1.3.6.1.2.1.2.2.1.2.25");
	ok(test_encode_string_oid(oid, 23, "\x06\x0a\x2b\x06\x01\x02\x01\x02\x02\x01\x02\x19", 12),
	    "encode_string_oid .1.3.6.1.2.1.2.2.1.2.25");
	ok(test_encode_string_oid("1.3.6.1.4.1.2636.3.5.2.1.5.33.118.54.95.73.78.70.82.65.95.67.79.78.78.69.67.84.95.86.49.45.103.101.45.50.47.49.47.48.46.51.56.45.105.81.118.54.95.73.78.70.82.65.95.68.69.70.95.73.67.77.80.95.73.78.70.79.82.77.65.84.73.79.78.65.76.45.118.54.95.73.78.70.82.65.95.67.79.78.78.69.67.84.95.73.67.77.80.95.73.78.70.79.82.77.65.84.73.79.78.65.76.45.103.101.45.50.47.49.47.48.46.51.56.45.105.3", -1,
					"\x06\x81\x81\x2b\x06\x01\x04\x01\x94\x4c\x03\x05\x02\x01\x05\x21\x76\x36\x5f\x49\x4e\x46\x52\x41\x5f\x43\x4f\x4e\x4e\x45\x43\x54\x5f\x56\x31\x2d\x67\x65\x2d\x32\x2f\x31\x2f\x30\x2e\x33\x38\x2d\x69\x51\x76\x36\x5f\x49\x4e\x46\x52\x41\x5f\x44\x45\x46\x5f\x49\x43\x4d\x50\x5f\x49\x4e\x46\x4f\x52\x4d\x41\x54\x49\x4f\x4e\x41\x4c\x2d\x76\x36\x5f\x49\x4e\x46\x52\x41\x5f\x43\x4f\x4e\x4e\x45\x43\x54\x5f\x49\x43\x4d\x50\x5f\x49\x4e\x46\x4f\x52\x4d\x41\x54\x49\x4f\x4e\x41\x4c\x2d\x67\x65\x2d\x32\x2f\x31\x2f\x30\x2e\x33\x38\x2d\x69\x03",
					132),
	    "encode_string_oid long numeric-tail oid");
	ok(test_encode_string_oid("1.3.6.1.2.1.47.1.3.1.1.1.1.1954816511", -1,
					"\x06\x11\x2b\x06\x01\x02\x01\x2f\x01\x03\x01\x01\x01\x01\x87\xa4\x90\xc3\x7f",
					19),
	    "encode_string_oid 1.3.6.1.2.1.47.1.3.1.1.1.1.1954816511");
	ok(test_encode_string("\x04\x01x", 2), "encode_string short");
	ok(test_encode_string("\x04\x06public", 2), "encode_string public");
	ok(test_encode_string("\x04\x81\x97"
		"Every inch of wall space is covered by a bookcase. "
		"Each bookcase has six shelves, going almost to the ceiling. "
		"Some bookshelves are stacked to the brim", 3),
	    "encode_string bookcase (1-byte length)");
	ok(test_encode_string("\x04\x82\x02\x2a"
		"Every inch of wall space is covered by a bookcase. "
		"Each bookcase has six shelves, going almost to the ceiling. "
		"Some bookshelves are stacked to the brim with hardcover books: "
		"science, mathematics, history, and everything else. "
		"Other shelves have two layers of paperback science fiction, "
		"with the back layer of books propped up on old tissue boxes or "
		"two-by-fours, so that you can see the back layer of books "
		"above the books in front. And it still isn't enough. "
		"Books are overflowing onto the tables and the sofas "
		"and making little heaps under the windows.", 4),
	    "encode_string bookcase (2-byte length)");

	ok(test_oid_compare(
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.991735.35946496.1358.1",
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000745.35946496.1519.1",
		-1),
	    "oid_compare .991735... vs .10000745... (-1)");
	ok(test_oid_compare(
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000745.35946496.1519.1",
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.991735.35946496.1358.1",
		+1),
	    "oid_compare .10000745... vs .991735... (+1)");
	ok(test_oid_compare(
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000744.35946496.1519.1",
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000745.35946496.1519.1",
		-1),
	    "oid_compare .10000744... vs .10000745... (-1)");
	ok(test_oid_compare(
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000745.35946496.1519.1",
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000744.35946496.1519.1",
		+1),
	    "oid_compare .10000745... vs .10000744... (+1)");
	ok(test_oid_compare(
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000745.35946496.1519.1",
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000745.35946496.1519.1",
		0),
	    "oid_compare equal oids (0)");

	ok(test_encode_integer(0, 0, "\x02\x01\x00", 3), "encode_integer 0");
	ok(test_encode_integer(127, 0, "\x02\x01\x7f", 3), "encode_integer 127");
	ok(test_encode_integer(128, 0, "\x02\x02\x00\x80", 4), "encode_integer 128");
	ok(test_encode_integer(255, 0, "\x02\x02\x00\xff", 4), "encode_integer 255");
	ok(test_encode_integer(256, 0, "\x02\x02\x01\x00", 4), "encode_integer 256");
	ok(test_encode_integer(32767, 0, "\x02\x02\x7f\xff", 4), "encode_integer 32767");
	ok(test_encode_integer(32768, 0, "\x02\x03\x00\x80\x00", 5), "encode_integer 32768");
	ok(test_encode_integer(65507, 0, "\x02\x03\x00\xff\xe3", 5), "encode_integer 65507");
	ok(test_encode_integer(65535, 0, "\x02\x03\x00\xff\xff", 5), "encode_integer 65535");
	ok(test_encode_integer(65536, 0, "\x02\x03\x01\x00\x00", 5), "encode_integer 65536");
	ok(test_encode_integer(0x7fffff, 0, "\x02\x03\x7f\xff\xff", 5), "encode_integer 0x7fffff");
	ok(test_encode_integer(0x800000, 0, "\x02\x04\x00\x80\x00\x00", 6), "encode_integer 0x800000");
	ok(test_encode_integer(0x1000000, 0, "\x02\x04\x01\x00\x00\x00", 6), "encode_integer 0x1000000");
	ok(test_encode_integer(0x7fffffff, 0, "\x02\x04\x7f\xff\xff\xff", 6), "encode_integer 0x7fffffff");
	ok(test_encode_integer(0x80000000u, 0, "\x02\x05\x00\x80\x00\x00\x00", 7), "encode_integer 0x80000000");
	ok(test_encode_integer(0xffffffffu, 0, "\x02\x05\x00\xff\xff\xff\xff", 7), "encode_integer 0xffffffff");
	ok(test_encode_integer(6789012, 4, "\x02\x04\x00\x67\x97\x94", 6), "encode_integer 6789012 force_size=4");
	ok(test_encode_integer(0x01020304, 4, "\x02\x04\x01\x02\x03\x04", 6), "encode_integer 0x01020304 force_size=4");

	ok(test_next_sid_from(0x01000000, 0x01000001), "next_sid_from 0x01000000");
	ok(test_next_sid_from(0x01ffffff, 0x02000000), "next_sid_from 0x01ffffff");
	ok(test_next_sid_from(0x7ffffffe, 0x7fffffff), "next_sid_from 0x7ffffffe");
	ok(test_next_sid_from(0x7fffffff, 0x01000000), "next_sid_from 0x7fffffff wraps");
	ok(test_next_sid_from(0xffffffffu, 0x01000000), "next_sid_from 0xffffffff wraps");
	ok(test_next_sid_from(0, 0x01000001), "next_sid_from 0");

	ok(test_v3_header_encoding(), "v3_header_encoding");
	ok(test_v2c_getbulk_packet(100, "\x02\x01\x64"), "v2c_getbulk_packet max_repetitions=100");
	ok(test_v2c_getbulk_packet(200, "\x02\x01\x7f"), "v2c_getbulk_packet max_repetitions=200");

	return tap_done();
}

