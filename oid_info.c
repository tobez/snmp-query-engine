#include "sqe.h"

int
free_oid_info_list(struct oid_info_head *list)
{
	struct oid_info *n1, *n2;

	n1 = TAILQ_FIRST(list);
	while (n1 != NULL) {
		n2 = TAILQ_NEXT(n1, oid_list);
		free(n1->oid.buf);
		free(n1->value.buf);
		free(n1);
		n1 = n2;
	}
	TAILQ_INIT(list);
	return 1;
}

int
allocate_oid_info_list(struct oid_info_head *list, msgpack_object *o, struct cid_info *ci)
{
	int i;
	struct oid_info *oi;
	char tmp_buf[2048];
	struct encode e;

	for (i = 0; i < o->via.array.size; i++) {
		if (o->via.array.ptr[i].type != MSGPACK_OBJECT_RAW) goto not_good;
		e = encode_init(tmp_buf, 2048);
		if (encode_string_oid(o->via.array.ptr[i].via.raw.ptr, o->via.array.ptr[i].via.raw.size, &e) < 0)	goto not_good;

		oi = malloc(sizeof(*oi));
		if (!oi)
			croak(2, "allocate_oid_info_list: malloc(oid_info)");
		bzero(oi, sizeof(*oi));
		oi->cid = ci->cid;
		oi->fd  = ci->fd;
		oi->oid = encode_dup(&e);

		TAILQ_INSERT_TAIL(list, oi, oid_list);
	}
	return o->via.array.size;

not_good:
	free_oid_info_list(list);
	return 0;
}
