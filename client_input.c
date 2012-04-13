#include "sqe.h"

static int
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

	if (write(si->fd, buffer->data, buffer->size) < 0)
		croak(1, "error_reply: write");
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
	return -1;
}

/*
 * get request:
 * [ 0, $cid, $ip, $port, $version, $community, [$oids], {other parameters} ]
 *
 */

static int
handle_get_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	unsigned ver = 0;
	unsigned port = 65536;
	char community[256];
	struct in_addr ip;
	struct client_requests_info *cri;

	if (o->via.array.size < 7 || o->via.array.size > 8)
		return error_reply(si, 20, cid, "bad request length");

	if (o->via.array.ptr[RI_GET_SNMP_VER].type == MSGPACK_OBJECT_POSITIVE_INTEGER)
		ver = o->via.array.ptr[RI_GET_SNMP_VER].via.u64;
	if (ver != 1 && ver != 2)
		return error_reply(si, 20, cid, "bad SNMP version");

	if (o->via.array.ptr[RI_GET_PORT].type == MSGPACK_OBJECT_POSITIVE_INTEGER)
		port = o->via.array.ptr[RI_GET_PORT].via.u64;
	if (port > 65535)
		return error_reply(si, 20, cid, "bad port number");

	if (!object2ip(&o->via.array.ptr[RI_GET_IP], &ip))
		return error_reply(si, 20, cid, "bad IP");

	if (!object2string(&o->via.array.ptr[RI_GET_COMMUNITY], community, 256))
		return error_reply(si, 20, cid, "bad community");

	if (o->via.array.ptr[RI_GET_OIDS].type != MSGPACK_OBJECT_ARRAY)
		return error_reply(si, 20, cid, "oids must be an array");
	if (o->via.array.ptr[RI_GET_OIDS].via.array.size < 1)
		return error_reply(si, 20, cid, "oids is an empty array");

	cri = get_client_requests_info(&ip, port, si->fd);
	strcpy(cri->dest->community, community);
	cri->dest->version = ver;

	return error_reply(si, 20, cid, "not implemented");
}

static void
client_input(struct socket_info *si)
{
	struct client_connection *c = si->udata;
	char buf[1500];
	int n;
	int got = 0;

	if (!c)
		croak(1, "client_input: no client_connection information");
	if ( (n = read(si->fd, buf, 1500)) == -1)
		croak(1, "client_input: read error");
	if (n == 0) {
		si->udata = NULL;
		delete_socket_info(si);
		msgpack_unpacked_destroy(&c->input);
		msgpack_unpacker_destroy(&c->unpacker);
		free(c);
		if (!opt_quiet)
			fprintf(stderr, "client disconnect\n");
		return;
	}

	msgpack_unpacker_reserve_buffer(&c->unpacker, n);
	memcpy(msgpack_unpacker_buffer(&c->unpacker), buf, n);
	msgpack_unpacker_buffer_consumed(&c->unpacker, n);

	while (msgpack_unpacker_next(&c->unpacker, &c->input)) {
		msgpack_object *o;
		uint32_t cid;
		uint32_t type;

		got = 1;
		if (!opt_quiet) {
			printf("got client input: ");
			msgpack_object_print(stdout, c->input.data);
			printf("\n");
		}
		o = &c->input.data;
		if (o->type != MSGPACK_OBJECT_ARRAY) {
			error_reply(si, 30, 0, "Request is not an array");
			goto end;
		}
		if (o->via.array.size < 1) {
			error_reply(si, 30, 0, "Request is an empty array");
			goto end;
		}
		if (o->via.array.size < 2) {
			error_reply(si, 30, 0, "Request without an id");
			goto end;
		}
		if (o->via.array.ptr[RI_CID].type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
			error_reply(si, 30, 0, "Request id is not a positive integer");
			goto end;
		}
		cid = o->via.array.ptr[RI_CID].via.u64;
		if (o->via.array.ptr[RI_TYPE].type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
			error_reply(si, 30, cid, "Request type is not a positive integer");
			goto end;
		}
		type = o->via.array.ptr[RI_TYPE].via.u64;
		switch (type) {
		case RT_GET:
			handle_get_request(si, cid, o);
			break;
		default:
			error_reply(si, type+20, cid, "Unknown request type");
		}
end:;
	}
	if (got) {
		msgpack_unpacker_expand_buffer(&c->unpacker, 0);
	}
}

void new_client_connection(int fd)
{
	struct socket_info *si;
	struct client_connection *c;

	si = new_socket_info(fd);
	c = malloc(sizeof(*c));
	if (!c)
		croak(1, "new_client_connection: malloc(client_connection)");
	bzero(c, sizeof(*c));
	si->udata = c;
	msgpack_unpacker_init(&c->unpacker, MSGPACK_UNPACKER_INIT_BUFFER_SIZE);
	msgpack_unpacked_init(&c->input);
	on_read(si, client_input);
}
