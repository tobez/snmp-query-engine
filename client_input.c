#include "sqe.h"

/*
 * get request:
 * [ 0, $id, $ip, $port, $version, $community, [$oids], {other parameters} ]
 *
 */

static void
error_reply(struct socket_info *si, unsigned code, unsigned id, char *error)
{
	msgpack_sbuffer* buffer = msgpack_sbuffer_new();
	msgpack_packer* pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	int l = strlen(error);

	msgpack_pack_array(pk, 3);
	msgpack_pack_int(pk, code);
	msgpack_pack_int(pk, id);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, error, l);

	if (write(si->fd, buffer->data, buffer->size) < 0)
		croak(1, "error_reply: write");
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
}

static void
handle_get_request(struct socket_info *si, unsigned id, msgpack_object *o)
{
	error_reply(si, 20, id, "Get request not implemented yet");
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
		uint32_t id;
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
		if (o->via.array.ptr[1].type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
			error_reply(si, 30, 0, "Request id is not a positive integer");
			goto end;
		}
		id = o->via.array.ptr[1].via.u64;
		if (o->via.array.ptr[0].type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
			error_reply(si, 30, id, "Request type is not a positive integer");
			goto end;
		}
		type = o->via.array.ptr[0].via.u64;
		switch (type) {
		case 0:
			handle_get_request(si, id, o);
			break;
		default:
			error_reply(si, type+20, id, "Unknown request type");
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
