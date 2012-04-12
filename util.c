#include "sqe.h"

char *
object2string(msgpack_object *o)
{
	char *s;

	if (o->type != MSGPACK_OBJECT_RAW)
		return NULL;

	s = malloc(o->via.raw.size + 1);
	if (!s)
		croak(1, "object2string: malloc(%d)", o->via.raw.size + 1);
	memcpy(s, o->via.raw.ptr, o->via.raw.size);
	s[o->via.raw.size] = 0;
	return s;
}

int
object2ip(msgpack_object *o, struct in_addr *ip)
{
	char *s = object2string(o);
	if (!s)	return 0;
	if (inet_aton(s, ip)) {
		free(s);
		return 1;
	}
	free(s);
	return 0;
}
