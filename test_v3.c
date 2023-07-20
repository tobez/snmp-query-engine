/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2023, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

int
main(void)
{
	int success = 0;
	int n_tests = 0;
    char *expect;
    char buf[64], buf2[64];
    char *sbuf;
    unsigned len;
    char *err;

    n_tests++;
    expect = "\x9f\xb5\xcc\x03\x81\x49\x7b\x37\x93\x52\x89\x39\xff\x78\x8d\x5d\x79\x14\x52\x11";
    if (password_to_key(V3O_AUTH_PROTO_SHA1, "maplesyrup", strlen("maplesyrup"), buf, 64, &len, &err)) {
        success++;
        n_tests++;
        if (len == 20)
          success++;
        else
          fprintf(stderr, "test %d, password_to_key: len != 20\n", n_tests);
        n_tests++;
        if (memcmp(expect, buf, 20) == 0)
          success++;
        else
          fprintf(stderr, "test %d, password_to_key: keys differ\n", n_tests);
    } else {
		fprintf(stderr, "test %d, password_to_key: %s\n", n_tests, err);
    }

    n_tests++;
    sbuf = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02";
    expect = "\x66\x95\xfe\xbc\x92\x88\xe3\x62\x82\x23\x5f\xc7\x15\x1f\x12\x84\x97\xb3\x8f\x3f";
    if (key_to_kul(V3O_AUTH_PROTO_SHA1, buf, 20, sbuf, 12, buf2, 64, &len, &err)) {
        success++;
        n_tests++;
        if (len == 20)
          success++;
        else
          fprintf(stderr, "test %d, localize_key: len != 20\n", n_tests);
        n_tests++;
        if (memcmp(expect, buf2, 20) == 0)
          success++;
        else
          fprintf(stderr, "test %d, localize_key: keys differ\n", n_tests);
    } else {
		fprintf(stderr, "test %d, localize_key: %s\n", n_tests, err);
    }

	fprintf(stderr, "%d of %d tests passed succesfully\n", success, n_tests);
    return success != n_tests;
}