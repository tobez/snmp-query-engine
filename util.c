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

static int sid_initialized = 0;
static unsigned sid;

unsigned
next_sid(void)
{
	if (!sid_initialized) {
		sid_initialized = 1;
		/* XXX use randomness here */
		sid = 123456;
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

	for (i = 0; i < len; i++) {
		fprintf(f, "%02x ", (unsigned)s[i]);
		if (i % 16 == 15 && i < len-1) {
			int j;
			fprintf(f, "  ");
			for (j = i - 16; j <= i; j++) {
				fprintf(f, "%c", isprint(s[j]) ? s[j] : '.');
			}
			fprintf(f, "\n");
		}
	}
	fprintf(f, "\n");
}
