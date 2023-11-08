/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2013, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

static void
client_gone(struct socket_info *si)
{
	struct client_connection *c = si->udata;

	PS.active_client_connections--;

	si->udata = NULL;
	free_all_client_request_info_for_fd(si->fd);
	delete_socket_info(si);
	if (c) {
		msgpack_unpacked_destroy(&c->input);
		msgpack_unpacker_destroy(&c->unpacker);
		free(c);
	}
	if (!opt_quiet)
		fprintf(stderr, "client disconnect\n");
}

static void
client_input(struct socket_info *si)
{
	struct client_connection *c = si->udata;
	uint8_t buf[16384];
	int n;
	int got = 0;
	int ok;

	if (!c)
		croak(1, "client_input: no client_connection information");
	if ( (n = read(si->fd, buf, 16384)) == -1) {
		switch (errno) {
		case EPIPE:
			client_gone(si);
			return;
		case ECONNRESET:
			client_gone(si);
			return;
		}
		croak(1, "client_input: read error");
	}
	if (n == 0) {
		client_gone(si);
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
		ok = -1;
		PS.client_requests++;
		si->PS.client_requests++;

		//if (!opt_quiet) {
		//	printf("got client input: ");
		//	msgpack_object_print(stdout, c->input.data);
		//	printf("\n");
		//}
		o = &c->input.data;
		if (o->type != MSGPACK_OBJECT_ARRAY) {
			error_reply(si, RT_ERROR, 0, "Request is not an array");
			goto end;
		}
		if (o->via.array.size < 1) {
			error_reply(si, RT_ERROR, 0, "Request is an empty array");
			goto end;
		}
		if (o->via.array.size < 2) {
			error_reply(si, RT_ERROR, 0, "Request without an id");
			goto end;
		}
		if (o->via.array.ptr[RI_CID].type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
			error_reply(si, RT_ERROR, 0, "Request id is not a positive integer");
			goto end;
		}
		cid = o->via.array.ptr[RI_CID].via.u64;
		if (o->via.array.ptr[RI_TYPE].type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
			error_reply(si, RT_ERROR, cid, "Request type is not a positive integer");
			goto end;
		}
		type = o->via.array.ptr[RI_TYPE].via.u64;
        switch (type) {
        case RT_SETOPT:
            ok = handle_setopt_request(si, cid, o);
            if (ok < 0) {
                fprintf(stderr, "there was a problem handling setopt: \n");
                msgpack_object_print(stderr, *o);
            }
            break;
        case RT_GETOPT:
            ok = handle_getopt_request(si, cid, o);
            break;
        case RT_INFO:
            ok = handle_info_request(si, cid, o);
            break;
        case RT_DEST_INFO:
            ok = handle_dest_info_request(si, cid, o);
            break;
        case RT_GET:
            ok = handle_get_request(si, cid, o);
            break;
        case RT_GETTABLE:
            ok = handle_gettable_request(si, cid, o);
            break;
        default:
            error_reply(si, type | RT_ERROR, cid, "Unknown request type");
        }
end:
		if (ok < 0) {
			PS.invalid_requests++;
			si->PS.invalid_requests++;
		}
	}
	if (got) {
		msgpack_unpacker_expand_buffer(&c->unpacker, 0);
	}
}

void new_client_connection(int fd)
{
	struct socket_info *si;
	struct client_connection *c;
	int flags;

	if ( (flags = fcntl(fd, F_GETFL, 0)) < 0)
		croak(1, "new_client_connection: fcntl(F_GETFL)");
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		croak(1, "new_client_connection: fcntl(F_SETFL)");
	#if defined(SO_NOSIGPIPE)
	{
		int no_sigpipe = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof (no_sigpipe)) < 0)
			croak(1, "new_client_connection: setsockopt of SO_NOSIGPIPE error");
	}
	#endif
	si = new_socket_info(fd);
	c = malloc(sizeof(*c));
	if (!c)
		croak(1, "new_client_connection: malloc(client_connection)");
	bzero(c, sizeof(*c));
	si->udata = c;

	PS.active_client_connections++;
	PS.total_client_connections++;

	msgpack_unpacker_init(&c->unpacker, MSGPACK_UNPACKER_INIT_BUFFER_SIZE);
	msgpack_unpacked_init(&c->input);
	on_eof(si, client_gone);
	on_read(si, client_input);
}
