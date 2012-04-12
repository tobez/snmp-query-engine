#include "sqe.h"

char *object_string(msgpack_object *o)
{
	char *s = malloc(o->via.raw.size + 1);
	if (!s)
		croak(1, "object_string: malloc(%d)", o->via.raw.size + 1);
	memcpy(s, o->via.raw.ptr, o->via.raw.size);
	s[o->via.raw.size] = 0;
	return s;
}
