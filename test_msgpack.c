#include "sqe.h"

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
	msgpack_unpacked result;

	(void)buf2; (void)buf2_len;

	msgpack_unpacker_init(&unpacker, MSGPACK_UNPACKER_INIT_BUFFER_SIZE);
	msgpack_unpacker_reserve_buffer(&unpacker, buf1_len-1);
	memcpy(msgpack_unpacker_buffer(&unpacker), buf1, buf1_len-1);
	msgpack_unpacker_buffer_consumed(&unpacker, buf1_len-1);

	msgpack_unpacked_init(&result);
	while (msgpack_unpacker_next(&unpacker, &result)) {
		msgpack_object_print(stdout, result.data);
		printf("\n");
	}

	return 0;
}
