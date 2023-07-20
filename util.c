/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2013, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

char *
object_strdup(msgpack_object *o)
{
	char *s;

	if (o->type == MSGPACK_OBJECT_BIN) {
		s = malloc(o->via.bin.size + 1);
		if (!s)
			croak(1, "object_strdup: malloc(%d)", o->via.bin.size + 1);
		memcpy(s, o->via.bin.ptr, o->via.bin.size);
		s[o->via.bin.size] = 0;
	} else if (o->type == MSGPACK_OBJECT_STR) {
		s = malloc(o->via.str.size + 1);
		if (!s)
			croak(1, "object_strdup: malloc(%d)", o->via.str.size + 1);
		memcpy(s, o->via.str.ptr, o->via.str.size);
		s[o->via.str.size] = 0;
	} else {
		return NULL;
	}
	return s;
}

char *
object2string(msgpack_object *o, char s[], int bufsize)
{
	switch (o->type) {
	case MSGPACK_OBJECT_BIN:
		if (o->via.bin.size >= bufsize)    return NULL;
		memcpy(s, o->via.bin.ptr, o->via.bin.size);
		s[o->via.bin.size] = 0;
		break;
	case MSGPACK_OBJECT_STR:
		if (o->via.str.size >= bufsize)    return NULL;
		memcpy(s, o->via.str.ptr, o->via.str.size);
		s[o->via.str.size] = 0;
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

size_t
object_hexstring_to_buffer(msgpack_object *o, uint8_t *buf, size_t bufsize)
{
	const char *s = NULL;
	uint32_t sz;
	int digits = 0;
	uint8_t b = 0;
	uint8_t nibble;
	size_t l = 0;

	switch (o->type) {
	case MSGPACK_OBJECT_BIN:
		sz = o->via.bin.size;
		s = o->via.bin.ptr;
		break;

	case MSGPACK_OBJECT_STR:
		sz = o->via.str.size;
		s = o->via.str.ptr;
		break;
	
	default:
		return -1;
	}

	while (sz) {
		if (*s >= '0' && *s <= '9') {
			nibble = *s - '0';
		} else if (*s >= 'a' && *s <= 'f') {
			nibble = *s - 'a' + 10;
		} else if (*s >= 'A' && *s <= 'F') {
			nibble = *s - 'A' + 10;
		} else if (*s == ' ') {
			s++;
			sz--;
			continue;
		} else {
			return -1;
		}
		s++;
		sz--;
		if (digits % 2 == 0) {
			b = nibble << 4;
		} else {
			b |= nibble;
			if (l >= bufsize)
				return -1;
			buf[l++] = b;
		}
		digits++;
	}
	if (digits % 2 != 0)
		return -1;
	return l;
}

int
object_string_eq(msgpack_object *o, char *s)
{
	int l;
	if (o->type == MSGPACK_OBJECT_BIN) {
		l = strlen(s);
		if (o->via.bin.size != l) return 0;
		return strncmp(o->via.bin.ptr, s, l) == 0;
	} else if (o->type == MSGPACK_OBJECT_STR) {
		l = strlen(s);
		if (o->via.str.size != l) return 0;
		return strncmp(o->via.str.ptr, s, l) == 0;
	} else {
		return 0;
	}
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
	// hack to make sure it will be coded as 4 bytes while being DER
	sid |= 0x01000000;
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

