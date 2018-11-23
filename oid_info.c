/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2013, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

int
free_oid_info_list(struct oid_info_head *list)
{
	struct oid_info *n1, *n2;

	n1 = TAILQ_FIRST(list);
	while (n1 != NULL) {
		n2 = TAILQ_NEXT(n1, oid_list);
if (0){
fprintf(stderr, "       freeing an oid (C:%u,S:%u) %s\n", n1->cid, n1->sid, oid2str(n1->oid));
}
		free(n1->oid.buf);
		free(n1->value.buf);
		PS.active_oid_infos--;
		free(n1);
		n1 = n2;
	}
	TAILQ_INIT(list);
	return 1;
}

int
free_oid_info(struct oid_info *oi)
{
	free(oi->oid.buf);
	free(oi->value.buf);
	PS.active_oid_infos--;
	free(oi);
	return 1;
}

int
allocate_oid_info_list(struct oid_info_head *list, msgpack_object *o, struct cid_info *ci)
{
	int i;
	struct oid_info *oi;
	char tmp_buf[2048];
	struct ber e;

	for (i = 0; i < o->via.array.size; i++) {
		if (o->via.array.ptr[i].type == MSGPACK_OBJECT_BIN) {
			e = ber_init(tmp_buf, 2048);
			if (encode_string_oid(o->via.array.ptr[i].via.bin.ptr, o->via.array.ptr[i].via.bin.size, &e) < 0)	goto not_good;
		} else if (o->via.array.ptr[i].type == MSGPACK_OBJECT_STR) {
			e = ber_init(tmp_buf, 2048);
			if (encode_string_oid(o->via.array.ptr[i].via.str.ptr, o->via.array.ptr[i].via.str.size, &e) < 0)	goto not_good;
		} else {
			goto not_good;
		}

		oi = malloc(sizeof(*oi));
		if (!oi)
			croak(2, "allocate_oid_info_list: malloc(oid_info)");
		PS.active_oid_infos++;
		PS.total_oid_infos++;
		bzero(oi, sizeof(*oi));
		oi->cid = ci->cid;
		oi->fd  = ci->fd;
		oi->oid = ber_dup(&e);

		TAILQ_INSERT_TAIL(list, oi, oid_list);
	}
	return o->via.array.size;

not_good:
	free_oid_info_list(list);
	return 0;
}

struct oid_info *
allocate_oid_info(msgpack_object *o, struct cid_info *ci)
{
	struct oid_info *oi;
	char tmp_buf[2048];
	struct ber e;

	if (o->type == MSGPACK_OBJECT_BIN) {
		e = ber_init(tmp_buf, 2048);
		if (encode_string_oid(o->via.bin.ptr, o->via.bin.size, &e) < 0)	return NULL;
	} else if (o->type == MSGPACK_OBJECT_STR) {
		e = ber_init(tmp_buf, 2048);
		if (encode_string_oid(o->via.str.ptr, o->via.str.size, &e) < 0)	return NULL;
	} else {
		return NULL;
	}

	oi = malloc(sizeof(*oi));
	if (!oi)
		croak(2, "allocate_oid_info: malloc(oid_info)");
	PS.active_oid_infos++;
	PS.total_oid_infos++;
	bzero(oi, sizeof(*oi));
	oi->cid = ci->cid;
	oi->fd  = ci->fd;
	oi->oid = ber_dup(&e);

	return oi;
}

void
dump_oid_info(msgpack_packer *pk, struct oid_info *oi)
{
	#define DUMPi(field) msgpack_pack_named_int(pk, #field, oi->field)
	msgpack_pack_map(pk, 6);

	DUMPi(sid);
	DUMPi(cid);
	DUMPi(fd);
	DUMPi(max_repetitions);
	msgpack_pack_string(pk, "oid");
	msgpack_pack_oid(pk, oi->oid);
	msgpack_pack_string(pk, "value");
	if (!oi->value.buf)
		msgpack_pack_nil(pk);
	else
		msgpack_pack_ber(pk, oi->value);

	#undef DUMPi
}
