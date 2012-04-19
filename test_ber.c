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
main(void)
{
	int success = 0;
	int n_tests = 0;
	char oid[256];

	strcpy(oid, "1.3.6.1.2.1.2.2.1.2.1001");
	success += test_encode_string_oid(&n_tests, oid, 24, "\x06\x0b\x2b\x06\x01\x02\x01\x02\x02\x01\x02\x87\x69", 13);
	strcpy(oid, ".1.3.6.1.2.1.2.2.1.2.25");
	success += test_encode_string_oid(&n_tests, oid, 23, "\x06\x0a\x2b\x06\x01\x02\x01\x02\x02\x01\x02\x19", 12);
	success += test_encode_string_oid(&n_tests, "1.3.6.1.4.1.2636.3.5.2.1.5.33.118.54.95.73.78.70.82.65.95.67.79.78.78.69.67.84.95.86.49.45.103.101.45.50.47.49.47.48.46.51.56.45.105.81.118.54.95.73.78.70.82.65.95.68.69.70.95.73.67.77.80.95.73.78.70.79.82.77.65.84.73.79.78.65.76.45.118.54.95.73.78.70.82.65.95.67.79.78.78.69.67.84.95.73.67.77.80.95.73.78.70.79.82.77.65.84.73.79.78.65.76.45.103.101.45.50.47.49.47.48.46.51.56.45.105.3", -1,
					"\x06\x81\x81\x2b\x06\x01\x04\x01\x94\x4c\x03\x05\x02\x01\x05\x21\x76\x36\x5f\x49\x4e\x46\x52\x41\x5f\x43\x4f\x4e\x4e\x45\x43\x54\x5f\x56\x31\x2d\x67\x65\x2d\x32\x2f\x31\x2f\x30\x2e\x33\x38\x2d\x69\x51\x76\x36\x5f\x49\x4e\x46\x52\x41\x5f\x44\x45\x46\x5f\x49\x43\x4d\x50\x5f\x49\x4e\x46\x4f\x52\x4d\x41\x54\x49\x4f\x4e\x41\x4c\x2d\x76\x36\x5f\x49\x4e\x46\x52\x41\x5f\x43\x4f\x4e\x4e\x45\x43\x54\x5f\x49\x43\x4d\x50\x5f\x49\x4e\x46\x4f\x52\x4d\x41\x54\x49\x4f\x4e\x41\x4c\x2d\x67\x65\x2d\x32\x2f\x31\x2f\x30\x2e\x33\x38\x2d\x69\x03",
					132);
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
	fprintf(stderr, "%d of %d tests passed succesfully\n", success, n_tests);

	{
		struct ber e;
		char buf[1500];
		e = ber_init(buf, 1500);
		if (build_get_request_packet(1, "public",
			"1.3.6.1.2.1.2.2.1.2.1001\0"
			"1.3.6.1.2.1.2.2.1.2.25\0",
			6789012, &e) < 0)
		{
			perror("build_get_request_packet");
		} else {
			ber_dump(stderr, &e);
		}
	}
	return 0;
}

