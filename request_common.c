#include "sqe.h"

int
error_reply(struct socket_info *si, unsigned code, unsigned cid, char *error)
{
	msgpack_sbuffer* buffer = msgpack_sbuffer_new();
	msgpack_packer* pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	int l = strlen(error);

	msgpack_pack_array(pk, 3);
	msgpack_pack_int(pk, code);
	msgpack_pack_int(pk, cid);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, error, l);

	tcp_send(si, buffer->data, buffer->size);
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
	return -1;
}

int
msgpack_pack_named_int(msgpack_packer *pk, char *name, int val)
{
	int l = strlen(name);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, name, l);
	msgpack_pack_int(pk, val);
	return 0;
}

int
msgpack_pack_named_string(msgpack_packer *pk, char *name, char *val)
{
	int l = strlen(name);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, name, l);
	l = strlen(val);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, val, l);
	return 0;
}
