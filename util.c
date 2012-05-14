/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

char *
object_strdup(msgpack_object *o)
{
	char *s;

	if (o->type != MSGPACK_OBJECT_RAW)
		return NULL;

	s = malloc(o->via.raw.size + 1);
	if (!s)
		croak(1, "object_strdup: malloc(%d)", o->via.raw.size + 1);
	memcpy(s, o->via.raw.ptr, o->via.raw.size);
	s[o->via.raw.size] = 0;
	return s;
}

char *
object2string(msgpack_object *o, char s[], int bufsize)
{
	switch (o->type) {
	case MSGPACK_OBJECT_RAW:
		if (o->via.raw.size >= bufsize)    return NULL;
		memcpy(s, o->via.raw.ptr, o->via.raw.size);
		s[o->via.raw.size] = 0;
		break;
	case MSGPACK_OBJECT_POSITIVE_INTEGER:
		if (snprintf(s, bufsize, "%"PRIu64, o->via.u64) >= bufsize)
			return NULL;
		break;
	default:
		return NULL;
	}

	return s;
}

int
object_string_eq(msgpack_object *o, char *s)
{
	int l;
	if (o->type != MSGPACK_OBJECT_RAW) return 0;
	l = strlen(s);
	if (o->via.raw.size != l) return 0;
	return strncmp(o->via.raw.ptr, s, l) == 0;
}

int
object2ip(msgpack_object *o, struct in_addr *ip)
{
	char buf[16];
	if (!object2string(o, buf, 16))	return 0;
	return inet_pton(AF_INET, buf, ip);
}

static int sid_initialized = 0;
static unsigned sid;

unsigned
next_sid(void)
{
	struct timeval tv;
	if (!sid_initialized) {
		sid_initialized = 1;
		/* do we want better randomness than this - is it worth it? */
		gettimeofday(&tv, NULL);
		sid = (tv.tv_sec % 500009) + tv.tv_usec;
	}
	sid++;
	sid &= 0xffffffff;
	if (sid == 0)
		sid++;
	return sid;
}

void
dump_buf(FILE *f, void *buf, int len)
{
	unsigned char *s = buf;
	int i;
	char o[68];
	int pos[] = { 0,3,6,9,12,15,18,21,25,28,31,34,37,40,43,46 };
	char hex[] = "0123456789abcdef";

	while (len) {
		memset(o, ' ', 67);
		o[67] = 0;
		for (i = 0; i < 16 && len > 0; i++, len--, s++) {
			o[pos[i]] = hex[*s >> 4];
			o[pos[i]+1] = hex[*s & 0x0f];
			o[51+i] = isprint(*s) ? *s : '.';
		}
		fprintf(f, "%s\n", o);
	}
}

static char oid2str_buf[4096];

char *
oid2str(struct ber o)
{
	if (!decode_string_oid(o.buf, o.max_len, oid2str_buf, 4096))
		strcpy(oid2str_buf, "oid-too-long");
	return oid2str_buf;
}

