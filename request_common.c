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
msgpack_pack_named_int(msgpack_packer *pk, char *name, int64_t val)
{
	int l = strlen(name);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, name, l);
	msgpack_pack_int(pk, val);
	/* XXX */
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
	/* XXX */
	return 0;
}

int
msgpack_pack_options(msgpack_packer *pk, struct destination *d)
{
	msgpack_pack_map(pk, 8);
	msgpack_pack_named_string(pk, "ip", inet_ntoa(d->ip));
	msgpack_pack_named_int(pk, "port", d->port);
	msgpack_pack_named_string(pk, "community", d->community);
	msgpack_pack_named_int(pk, "version", d->version + 1);
	msgpack_pack_named_int(pk, "max_packets", d->max_packets_on_the_wire);
	msgpack_pack_named_int(pk, "max_req_size", d->max_request_packet_size);
	msgpack_pack_named_int(pk, "timeout", d->timeout);
	msgpack_pack_named_int(pk, "retries", d->retries);
	/* XXX */
	return 0;
}
