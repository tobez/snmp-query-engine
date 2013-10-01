/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2013, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

void
add_input_bytes(msgpack_unpacker *unpacker, char *buf, int sz)
{
	msgpack_unpacked result;
	int got = 0;

	printf("reading %d bytes\n", sz);
	//getchar();
	printf("ENT u(%u) f(%u) o(%u) p(%u)\n", (unsigned)unpacker->used, (unsigned)unpacker->free, (unsigned)unpacker->off, (unsigned)unpacker->parsed);
	msgpack_unpacker_reserve_buffer(unpacker, sz);
	printf("EXP u(%u) f(%u) o(%u) p(%u)\n", (unsigned)unpacker->used, (unsigned)unpacker->free, (unsigned)unpacker->off, (unsigned)unpacker->parsed);
	memcpy(msgpack_unpacker_buffer(unpacker), buf, sz);
	msgpack_unpacker_buffer_consumed(unpacker, sz);
	printf("CON u(%u) f(%u) o(%u) p(%u)\n", (unsigned)unpacker->used, (unsigned)unpacker->free, (unsigned)unpacker->off, (unsigned)unpacker->parsed);

	msgpack_unpacked_init(&result);
	while (msgpack_unpacker_next(unpacker, &result)) {
		got = 1;
		msgpack_object_print(stdout, result.data);
		printf("\n");
	}
	if (got) {
		msgpack_unpacker_expand_buffer(unpacker, 0);
		printf("XXX u(%u) f(%u) o(%u) p(%u)\n", (unsigned)unpacker->used, (unsigned)unpacker->free, (unsigned)unpacker->off, (unsigned)unpacker->parsed);
	}
	msgpack_unpacked_destroy(&result);
}

int
main(void)
{
	// [0,42,{key=>"value"},["1.2.3","4.5.6"]]
	char *buf1 = "\x94\x00\x2a\x81\xa3\x6b\x65\x79\xa5\x76\x61\x6c\x75\x65\x92\xa5\x31\x2e\x32\x2e\x33\xa5\x34\x2e\x35\x2e\x36";
	int buf1_len = 27;
	// ["ModeratelyLongStringLongerThan32Bytes",1,-2,{dict=>42}]
	char *buf2 = "\x94\xda\x00\x25\x4d\x6f\x64\x65\x72\x61\x74\x65\x6c\x79\x4c\x6f"
				 "\x6e\x67\x53\x74\x72\x69\x6e\x67\x4c\x6f\x6e\x67\x65\x72\x54\x68"
				 "\x61\x6e\x33\x32\x42\x79\x74\x65\x73\x01\xfe\x81\xa4\x64\x69\x63"
				 "\x74\x2a";
	int buf2_len = 50;
	msgpack_unpacker unpacker;

	msgpack_unpacker_init(&unpacker, MSGPACK_UNPACKER_INIT_BUFFER_SIZE);

	while (buf1_len) {
		add_input_bytes(&unpacker, buf1, 3);
		buf1_len -= 3;
		buf1 += 3;
		printf("buf1 len is now %d\n", buf1_len);
	}
	while (buf2_len) {
		add_input_bytes(&unpacker, buf2, 2);
		buf2_len -= 2;
		buf2 += 2;
		printf("buf2 len is now %d\n", buf2_len);
	}

	return 0;
}
