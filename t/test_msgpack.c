/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2013, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
/* ABOUTME: Tests streaming msgpack reassembly: feeds documents to a
 * ABOUTME: msgpack_unpacker in odd-sized chunks and asserts the decoded objects. */
#include "sqe.h"
#include "tap.h"

/* Feed sz bytes into the unpacker without extracting objects. */
static void
feed(msgpack_unpacker *unpacker, const char *buf, int sz)
{
	msgpack_unpacker_reserve_buffer(unpacker, sz);
	memcpy(msgpack_unpacker_buffer(unpacker), buf, sz);
	msgpack_unpacker_buffer_consumed(unpacker, sz);
}

int
main(void)
{
	/* [0,42,{"key":"value"},["1.2.3","4.5.6"]] */
	const char *buf1 = "\x94\x00\x2a\x81\xa3\x6b\x65\x79\xa5\x76\x61\x6c\x75\x65\x92\xa5\x31\x2e\x32\x2e\x33\xa5\x34\x2e\x35\x2e\x36";
	int buf1_len = 27;
	/* ["ModeratelyLongStringLongerThan32Bytes",1,-2,{"dict":42}] */
	const char *buf2 = "\x94\xda\x00\x25\x4d\x6f\x64\x65\x72\x61\x74\x65\x6c\x79\x4c\x6f"
	    "\x6e\x67\x53\x74\x72\x69\x6e\x67\x4c\x6f\x6e\x67\x65\x72\x54\x68"
	    "\x61\x6e\x33\x32\x42\x79\x74\x65\x73\x01\xfe\x81\xa4\x64\x69\x63"
	    "\x74\x2a";
	int buf2_len = 50;
	msgpack_unpacker unpacker;
	msgpack_unpacked result;
	msgpack_object o;

	msgpack_unpacker_init(&unpacker, MSGPACK_UNPACKER_INIT_BUFFER_SIZE);
	msgpack_unpacked_init(&result);

	/* document 1, fed in 3-byte chunks.  NB: each msgpack_unpacker_next()
	 * call releases the zone backing the previously returned object, so all
	 * assertions on a document happen before the next feed/next cycle. */
	while (buf1_len > 0) {
		int chunk = buf1_len < 3 ? buf1_len : 3;
		feed(&unpacker, buf1, chunk);
		if (buf1_len > chunk)
			ok(!msgpack_unpacker_next(&unpacker, &result),
			    "no object before document 1 is complete (%d bytes left)", buf1_len - chunk);
		buf1_len -= chunk;
		buf1 += chunk;
	}
	ok(msgpack_unpacker_next(&unpacker, &result), "document 1 complete after last chunk");

	o = result.data;
	is_int(o.type, MSGPACK_OBJECT_ARRAY, "doc1 is an array");
	is_int(o.via.array.size, 4, "doc1 has 4 elements");
	is_int(o.via.array.ptr[0].via.u64, 0, "doc1[0] == 0");
	is_int(o.via.array.ptr[1].via.u64, 42, "doc1[1] == 42");
	is_int(o.via.array.ptr[2].type, MSGPACK_OBJECT_MAP, "doc1[2] is a map");
	is_int(o.via.array.ptr[2].via.map.size, 1, "doc1[2] has 1 pair");
	ok(o.via.array.ptr[2].via.map.ptr[0].val.via.str.size == 5 &&
	    memcmp(o.via.array.ptr[2].via.map.ptr[0].val.via.str.ptr, "value", 5) == 0,
	    "doc1[2]{key} == \"value\"");
	is_int(o.via.array.ptr[3].type, MSGPACK_OBJECT_ARRAY, "doc1[3] is an array");
	is_int(o.via.array.ptr[3].via.array.size, 2, "doc1[3] has 2 elements");
	ok(o.via.array.ptr[3].via.array.ptr[1].via.str.size == 5 &&
	    memcmp(o.via.array.ptr[3].via.array.ptr[1].via.str.ptr, "4.5.6", 5) == 0,
	    "doc1[3][1] == \"4.5.6\"");

	/* document 2, fed in 2-byte chunks */
	while (buf2_len > 0) {
		int chunk = buf2_len < 2 ? buf2_len : 2;
		feed(&unpacker, buf2, chunk);
		if (buf2_len > chunk)
			ok(!msgpack_unpacker_next(&unpacker, &result),
			    "no object before document 2 is complete (%d bytes left)", buf2_len - chunk);
		buf2_len -= chunk;
		buf2 += chunk;
	}
	ok(msgpack_unpacker_next(&unpacker, &result), "document 2 complete after last chunk");

	o = result.data;
	is_int(o.type, MSGPACK_OBJECT_ARRAY, "doc2 is an array");
	is_int(o.via.array.size, 4, "doc2 has 4 elements");
	ok(o.via.array.ptr[0].via.str.size == 37 &&
	    memcmp(o.via.array.ptr[0].via.str.ptr,
	        "ModeratelyLongStringLongerThan32Bytes", 37) == 0,
	    "doc2[0] is the 37-byte string");
	is_int(o.via.array.ptr[1].via.u64, 1, "doc2[1] == 1");
	is_int(o.via.array.ptr[2].type, MSGPACK_OBJECT_NEGATIVE_INTEGER, "doc2[2] is negative");
	is_int(o.via.array.ptr[2].via.i64, -2, "doc2[2] == -2");
	is_int(o.via.array.ptr[3].via.map.ptr[0].val.via.u64, 42, "doc2[3]{dict} == 42");

	ok(!msgpack_unpacker_next(&unpacker, &result), "no extra objects");
	msgpack_unpacked_destroy(&result);
	msgpack_unpacker_destroy(&unpacker);

	/* feed_client_unpacker() feeds a chunk into a connection's unpacker and
	 * must report an allocation failure rather than memcpy into a buffer that
	 * was never reserved. */
	{
		struct client_connection c;
		msgpack_unpacked r;
		const uint8_t doc[] = "\x92\x01\x02"; /* [1,2] */

		msgpack_unpacker_init(&c.unpacker, MSGPACK_UNPACKER_INIT_BUFFER_SIZE);
		msgpack_unpacked_init(&r);

		is_int(feed_client_unpacker(&c, doc, 3), 0,
		    "feed_client_unpacker accepts a normal chunk");
		ok(msgpack_unpacker_next(&c.unpacker, &r), "fed document parses");
		is_int(r.data.via.array.size, 2, "fed document has 2 elements");

		is_int(feed_client_unpacker(&c, doc, (size_t)1 << 60), -1,
		    "feed_client_unpacker reports reserve failure instead of overrunning");

		msgpack_unpacked_destroy(&r);
		msgpack_unpacker_destroy(&c.unpacker);
	}

	return tap_done();
}
