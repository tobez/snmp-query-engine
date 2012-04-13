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
	if (o->type != MSGPACK_OBJECT_RAW) return NULL;
	if (o->via.raw.size >= bufsize)    return NULL;

	memcpy(s, o->via.raw.ptr, o->via.raw.size);
	s[o->via.raw.size] = 0;
	return s;
}

int
object2ip(msgpack_object *o, struct in_addr *ip)
{
	char buf[16];
	if (!object2string(o, buf, 16))	return 0;
	return inet_aton(buf, ip);
}
