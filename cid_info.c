#include "sqe.h"

struct cid_info *
get_cid_info(struct client_requests_info *cri, unsigned cid)
{
	struct cid_info **ci_slot, *ci;

	JLI(ci_slot, cri->cid_info, cid);
	if (ci_slot == PJERR)
		croak(2, "get_cid_info: JLI(cid) failed");
	if (!*ci_slot) {
		ci = malloc(sizeof(*ci));
		if (!ci)
			croak(2, "get_cid_info: malloc(cid_info)");
		bzero(ci, sizeof(*ci));
		ci->cri = cri;
		ci->fd = cri->fd;
		ci->cid = cid;
		TAILQ_INIT(&ci->oids_done);
		*ci_slot = ci;
	}
	return *ci_slot;
}

int
free_cid_info(struct cid_info *ci)
{
fprintf(stderr, "  freeing cid_info, fd %d, cid %u\n", ci->fd, ci->cid);
fprintf(stderr, "  n_oids(%d), n_oids_being_queried(%d), n_oids_done(%d)\n",
		ci->n_oids, ci->n_oids_being_queried, ci->n_oids_done);
fprintf(stderr, "     oids_done, fd %d, cid %u\n", ci->fd, ci->cid);
	free_oid_info_list(&ci->oids_done);
	free(ci);
	return 1;
}

void static inline
pack_error(msgpack_packer *pk, char *error)
{
	int l = strlen(error);
	msgpack_pack_array(pk, 1);
	msgpack_pack_raw(pk, l);
	msgpack_pack_raw_body(pk, error, l);
}

void
cid_reply(struct cid_info *ci)
{
	msgpack_sbuffer* buffer = msgpack_sbuffer_new();
	msgpack_packer* pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	struct oid_info *oi;
	char buf[4096];
	int l;

	msgpack_pack_array(pk, 3);
	msgpack_pack_int(pk, RT_GET|RT_REPLY);
	msgpack_pack_int(pk, ci->cid);
	msgpack_pack_array(pk, ci->n_oids_done);
	TAILQ_FOREACH(oi, &ci->oids_done, oid_list) {
		msgpack_pack_array(pk, 2);
		if (!decode_string_oid(oi->oid.buf, oi->oid.len, buf, 4096))
			strcpy(buf, "oid-too-long");
		l = strlen(buf);
		msgpack_pack_raw(pk, l);
		msgpack_pack_raw_body(pk, buf, l);
		switch (oi->value.buf[0]) {
		case AT_NULL:
			msgpack_pack_nil(pk);
			break;
		case AT_NO_SUCH_OBJECT:
			pack_error(pk, "no-such-object");
			break;
		case AT_NO_SUCH_INSTANCE:
			pack_error(pk, "no-such-instance");
			break;
		case AT_END_OF_MIB_VIEW:
			pack_error(pk, "end-of-mib");
			break;
		case VAL_TIMEOUT:
			pack_error(pk, "timeout");
			break;
		case VAL_MISSING:
			pack_error(pk, "missing");
			break;
		default:
			pack_error(pk, "unsupported");
		}
	}

	fprintf(stderr, "cid %u reply\n", ci->cid);
	tcp_send(ci->cri->si, buffer->data, buffer->size);
	msgpack_sbuffer_free(buffer);
	msgpack_packer_free(pk);
}
