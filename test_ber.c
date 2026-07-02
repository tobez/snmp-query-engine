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
test_encode_string_oid(int *test, char *oid, int oid_len, const char *res, int len)
{
	char *buf = malloc(len + 20);
	struct ber e = ber_init(buf, len + 20);
	char out_buf[4096];
	int oid_len2;

	(*test)++;
	buf[len] = '\x55';
	if (oid_len >= 0) {
		oid[oid_len] = '\xAA';
		oid_len2 = oid_len;
	} else {
		oid_len2 = strlen(oid);
	}
	if (encode_string_oid(oid, oid_len, &e) < 0) {
		fprintf(stderr, "test %d, encode_string_oid: unexpected failure, oid %s\n", *test, oid);
		free(buf);
		return 0;
	}
	if (oid_len >= 0 && oid[oid_len] != '\xAA') {
		fprintf(stderr, "test %d, encode_string_oid: corrupted OID string\n", *test);
		free(buf);
		return 0;
	}
	if (e.len != len) {
		fprintf(stderr, "test %d, encode_string_oid: unexpected length (%d != %d), oid %s\n", *test, e.len, len, oid);
		free(buf);
		return 0;
	}
	if (buf[len] != '\x55') {
		fprintf(stderr, "test %d, encode_string_oid: buffer corruped, oid %s\n", *test, oid);
		free(buf);
		return 0;
	}
	if (!decode_string_oid((unsigned char *)buf, len, out_buf, 4096)) {
		fprintf(stderr, "test %d, decode_string_oid: cannot decode encoded oid %s\n", *test, oid);
		free(buf);
		return 0;
	}
	// fprintf(stderr, "ORIGINAL: %s\nDECODED : %s\n", oid, out_buf);
	if (strlen(out_buf) != (*oid == '.' ? oid_len2-1 : oid_len2)) {
		fprintf(stderr, "test %d, decode_string_oid: decoded oid len != encoded oid len, %s\n", *test, oid);
		free(buf);
		return 0;
	}
	if (strncmp(*oid == '.' ? oid+1 : oid, out_buf, *oid == '.' ? oid_len2-1 : oid_len2) != 0) {
		fprintf(stderr, "test %d, decode_string_oid: decoded oid != encoded oid %s\n", *test, oid);
		free(buf);
		return 0;
	}
	if (memcmp(buf, res, len) != 0) {
		fprintf(stderr, "test %d, encode_string_oid: unexpected buffer content, oid %s\n", *test, oid);
		free(buf);
		return 0;
	}
	e = ber_init(buf, len);
	if (encode_string_oid(oid, oid_len, &e) < 0) {
		fprintf(stderr, "test %d, encode_string_oid: unexpected failure with just enough buffer space, oid %s\n", *test, oid);
		free(buf);
		return 0;
	}
	e = ber_init(buf, len-1);
	if (encode_string_oid(oid, oid_len, &e) == 0) {
		fprintf(stderr, "test %d, encode_string_oid: unexpected success with slightly not enough buffer space, oid %s\n", *test, oid);
		free(buf);
		return 0;
	}
	free(buf);
	return 1;
}

int
test_encode_string(int *test, const char *test_string, int real_string_offset)
{
	int len = strlen(test_string);
	const char *s = test_string + real_string_offset;
	char *buf = malloc(len + 20);
	struct ber e = ber_init(buf, len + 20);

	(*test)++;
	buf[len] = '\x55';
	if (encode_string(s, &e) < 0) {
		fprintf(stderr, "test %d, encode_string: unexpected failure, string %s\n", *test, s);
		free(buf);
		return 0;
	}
	if (e.len != len) {
		fprintf(stderr, "test %d, encode_string: unexpected length (%d != %d), string %s\n", *test, e.len, len, s);
		free(buf);
		return 0;
	}
	if (buf[len] != '\x55') {
		fprintf(stderr, "test %d, encode_string: buffer corruped, string %s\n", *test, s);
		free(buf);
		return 0;
	}
	if (memcmp(buf, test_string, len) != 0) {
		fprintf(stderr, "test %d, encode_string: unexpected buffer content, string %s\n", *test, s);
		free(buf);
		return 0;
	}
	e = ber_init(buf, len);
	if (encode_string(s, &e) < 0) {
		fprintf(stderr, "test %d, encode_string: unexpected failure with just enough buffer space, string %s\n", *test, s);
		free(buf);
		return 0;
	}
	e = ber_init(buf, len-1);
	if (encode_string(s, &e) == 0) {
		fprintf(stderr, "test %d, encode_string: unexpected success with slightly not enough buffer space, string %s\n", *test, s);
		free(buf);
		return 0;
	}
	free(buf);
	return 1;
}

int
test_oid_compare(int *test, const char *o1, const char *o2, int expected)
{
	char buf1[4096];
	char buf2[4096];
	struct ber oid1 = ber_init(buf1, 4096);
	struct ber oid2 = ber_init(buf2, 4096);
	int got;

	(*test)++;
	if (encode_string_oid(o1, -1, &oid1) < 0) {
		fprintf(stderr, "test %d, encode_string_oid: unexpected failure, oid %s\n", *test, o1);
		return 0;
	}
	if (encode_string_oid(o2, -1, &oid2) < 0) {
		fprintf(stderr, "test %d, encode_string_oid: unexpected failure, oid %s\n", *test, o2);
		return 0;
	}
	if ((got = oid_compare(&oid1, &oid2)) != expected) {
		fprintf(stderr, "test %d, oid_compare(\"%s\",\"%s\"): expected %d, got %d\n", *test, o1, o2, expected, got);
		return 0;
	}
	return 1;
}

int
test_encode_integer(int *test, unsigned value, int force_size, const char *res, int len)
{
	unsigned char buf[16];
	struct ber e = ber_init(buf, 16);
	unsigned decoded;

	(*test)++;
	if (encode_integer(value, &e, force_size) < 0) {
		fprintf(stderr, "test %d, encode_integer(%u,%d): unexpected failure\n", *test, value, force_size);
		return 0;
	}
	if (e.len != len) {
		fprintf(stderr, "test %d, encode_integer(%u,%d): unexpected length (%d != %d)\n", *test, value, force_size, e.len, len);
		return 0;
	}
	if (memcmp(buf, res, len) != 0) {
		fprintf(stderr, "test %d, encode_integer(%u,%d): unexpected buffer content\n", *test, value, force_size);
		return 0;
	}
	e = ber_init(buf, len);
	if (decode_integer(&e, -1, &decoded) < 0) {
		fprintf(stderr, "test %d, encode_integer(%u,%d): cannot decode encoded integer\n", *test, value, force_size);
		return 0;
	}
	if (decoded != value) {
		fprintf(stderr, "test %d, encode_integer(%u,%d): decode round-trip gave %u\n", *test, value, force_size, decoded);
		return 0;
	}
	return 1;
}

int
main(void)
{
	int success = 0;
	int n_tests = 0;
	char oid[256];
	struct in_addr ip;
	struct ber bt;
	unsigned char buf[80];

	n_tests++;
	bt.buf = buf;
	bt.b = buf;
	bt.len = 0;
	bt.max_len = 80;
	strcpy((char *)buf, "\x40\x04\xff\xff\xff\xfc");
	if (decode_ipv4_address(&bt, -1, &ip) < 0) {
		fprintf(stderr, "test %d, decode_ipv4_address: unexpected failure\n", n_tests);
	} else {
		if (strcmp(inet_ntoa(ip), "255.255.255.252") != 0)
			fprintf(stderr, "test %d, decode_ipv4_address: bad IP %s, expected 255.255.255.252\n", n_tests, inet_ntoa(ip));
		else
			success++;
	}

	strcpy(oid, "1.3.6.1.2.1.2.2.1.2.1001");
	success += test_encode_string_oid(&n_tests, oid, 24, "\x06\x0b\x2b\x06\x01\x02\x01\x02\x02\x01\x02\x87\x69", 13);
	strcpy(oid, ".1.3.6.1.2.1.2.2.1.2.25");
	success += test_encode_string_oid(&n_tests, oid, 23, "\x06\x0a\x2b\x06\x01\x02\x01\x02\x02\x01\x02\x19", 12);
	success += test_encode_string_oid(&n_tests, "1.3.6.1.4.1.2636.3.5.2.1.5.33.118.54.95.73.78.70.82.65.95.67.79.78.78.69.67.84.95.86.49.45.103.101.45.50.47.49.47.48.46.51.56.45.105.81.118.54.95.73.78.70.82.65.95.68.69.70.95.73.67.77.80.95.73.78.70.79.82.77.65.84.73.79.78.65.76.45.118.54.95.73.78.70.82.65.95.67.79.78.78.69.67.84.95.73.67.77.80.95.73.78.70.79.82.77.65.84.73.79.78.65.76.45.103.101.45.50.47.49.47.48.46.51.56.45.105.3", -1,
					"\x06\x81\x81\x2b\x06\x01\x04\x01\x94\x4c\x03\x05\x02\x01\x05\x21\x76\x36\x5f\x49\x4e\x46\x52\x41\x5f\x43\x4f\x4e\x4e\x45\x43\x54\x5f\x56\x31\x2d\x67\x65\x2d\x32\x2f\x31\x2f\x30\x2e\x33\x38\x2d\x69\x51\x76\x36\x5f\x49\x4e\x46\x52\x41\x5f\x44\x45\x46\x5f\x49\x43\x4d\x50\x5f\x49\x4e\x46\x4f\x52\x4d\x41\x54\x49\x4f\x4e\x41\x4c\x2d\x76\x36\x5f\x49\x4e\x46\x52\x41\x5f\x43\x4f\x4e\x4e\x45\x43\x54\x5f\x49\x43\x4d\x50\x5f\x49\x4e\x46\x4f\x52\x4d\x41\x54\x49\x4f\x4e\x41\x4c\x2d\x67\x65\x2d\x32\x2f\x31\x2f\x30\x2e\x33\x38\x2d\x69\x03",
					132);
	success += test_encode_string_oid(&n_tests, "1.3.6.1.2.1.47.1.3.1.1.1.1.1954816511", -1,
					"\x06\x11\x2b\x06\x01\x02\x01\x2f\x01\x03\x01\x01\x01\x01\x87\xa4\x90\xc3\x7f",
					19);
	success += test_encode_string(&n_tests, "\x04\x01x", 2);
	success += test_encode_string(&n_tests, "\x04\x06public", 2);
	success += test_encode_string(&n_tests, "\x04\x81\x97"
		"Every inch of wall space is covered by a bookcase. "
		"Each bookcase has six shelves, going almost to the ceiling. "
		"Some bookshelves are stacked to the brim", 3);
	success += test_encode_string(&n_tests, "\x04\x82\x02\x2a"
		"Every inch of wall space is covered by a bookcase. "
		"Each bookcase has six shelves, going almost to the ceiling. "
		"Some bookshelves are stacked to the brim with hardcover books: "
		"science, mathematics, history, and everything else. "
		"Other shelves have two layers of paperback science fiction, "
		"with the back layer of books propped up on old tissue boxes or "
		"two-by-fours, so that you can see the back layer of books "
		"above the books in front. And it still isn't enough. "
		"Books are overflowing onto the tables and the sofas "
		"and making little heaps under the windows.", 4);

	success += test_oid_compare(&n_tests,
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.991735.35946496.1358.1",
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000745.35946496.1519.1",
		-1);
	success += test_oid_compare(&n_tests,
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000745.35946496.1519.1",
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.991735.35946496.1358.1",
		+1);
	success += test_oid_compare(&n_tests,
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000744.35946496.1519.1",
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000745.35946496.1519.1",
		-1);
	success += test_oid_compare(&n_tests,
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000745.35946496.1519.1",
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000744.35946496.1519.1",
		+1);
	success += test_oid_compare(&n_tests,
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000745.35946496.1519.1",
		"1.3.6.1.4.1.6527.3.1.2.4.3.7.1.12.10000745.35946496.1519.1",
		0);

	success += test_encode_integer(&n_tests, 0, 0, "\x02\x01\x00", 3);
	success += test_encode_integer(&n_tests, 127, 0, "\x02\x01\x7f", 3);
	success += test_encode_integer(&n_tests, 128, 0, "\x02\x02\x00\x80", 4);
	success += test_encode_integer(&n_tests, 255, 0, "\x02\x02\x00\xff", 4);
	success += test_encode_integer(&n_tests, 256, 0, "\x02\x02\x01\x00", 4);
	success += test_encode_integer(&n_tests, 32767, 0, "\x02\x02\x7f\xff", 4);
	success += test_encode_integer(&n_tests, 32768, 0, "\x02\x03\x00\x80\x00", 5);
	success += test_encode_integer(&n_tests, 65507, 0, "\x02\x03\x00\xff\xe3", 5);
	success += test_encode_integer(&n_tests, 65535, 0, "\x02\x03\x00\xff\xff", 5);
	success += test_encode_integer(&n_tests, 65536, 0, "\x02\x03\x01\x00\x00", 5);
	success += test_encode_integer(&n_tests, 0x7fffff, 0, "\x02\x03\x7f\xff\xff", 5);
	success += test_encode_integer(&n_tests, 0x800000, 0, "\x02\x04\x00\x80\x00\x00", 6);
	success += test_encode_integer(&n_tests, 0x1000000, 0, "\x02\x04\x01\x00\x00\x00", 6);
	success += test_encode_integer(&n_tests, 0x7fffffff, 0, "\x02\x04\x7f\xff\xff\xff", 6);
	success += test_encode_integer(&n_tests, 0x80000000u, 0, "\x02\x05\x00\x80\x00\x00\x00", 7);
	success += test_encode_integer(&n_tests, 0xffffffffu, 0, "\x02\x05\x00\xff\xff\xff\xff", 7);
	success += test_encode_integer(&n_tests, 6789012, 4, "\x02\x04\x00\x67\x97\x94", 6);
	success += test_encode_integer(&n_tests, 0x01020304, 4, "\x02\x04\x01\x02\x03\x04", 6);

	fprintf(stderr, "%d of %d tests passed succesfully\n", success, n_tests);
	return success != n_tests;
}

