#include "sqe.h"

#define SPACECHECK(bytes) if (e->len + (bytes) > e->max_len) { errno = EMSGSIZE; return -1; }
#define SPACECHECK2 SPACECHECK(2)
#define EXTEND(bytes) { int sz = (bytes); e->len += sz; e->b += sz; }
#define EXTEND2 EXTEND(2)
#define OENDCHECK if (o >= oend) { errno = EINVAL; return -1; }

struct encode encode_init(void *buf, int size)
{
	struct encode e;
	e.buf = e.b = buf;
	e.len = 0;
	e.max_len = size;
	return e;
}

struct encode encode_dup(struct encode *eo)
{
	char *buf = malloc(eo->len);
	struct encode en;

	if (!buf)
		croak(2, "encode_dup: malloc(buf(%d))", eo->len);
	en = encode_init(buf, eo->len);
	memcpy(buf, eo->buf, eo->len);
	en.len = eo->len;
	en.b += eo->len;
	return en;
}

int
build_get_request_packet(int version, const char *community,
						 const char *oid_list,
						 unsigned request_id, struct encode *e)
{
	unsigned char *packet_sequence;
	unsigned char *pdu;
	unsigned char *oid_sequence;

	SPACECHECK2;
	packet_sequence = e->b;
   	packet_sequence[0] = AT_SEQUENCE;
	EXTEND2;

	if (version < 0 || version > 1) {
		errno = EINVAL;
		return -1;
	}
	if (encode_integer((unsigned)version, e, 0) < 0)	return -1;
	if (encode_string(community, e) < 0)	return -1;

	SPACECHECK2;
	pdu = e->b;
	pdu[0] = PDU_GET_REQUEST;
	EXTEND2;

	if (encode_integer(request_id, e, 4) < 0)	return -1;
	if (encode_integer(0, e, 0) < 0)	return -1; /* error-status */
	if (encode_integer(0, e, 0) < 0)	return -1; /* error-index */

	SPACECHECK2;
	oid_sequence = e->b;
	oid_sequence[0] = AT_SEQUENCE;
	EXTEND2;

	while (*oid_list) {
		unsigned char *seq;
		int l;

		SPACECHECK2;
		seq = e->b;
		seq[0] = AT_SEQUENCE;
		EXTEND2;
		l = encode_string_oid(oid_list, -1, e);
		if (l < 0)	return -1;
		SPACECHECK2;
		e->b[0] = AT_NULL;
		e->b[1] = 0;
		EXTEND2;
		if (encode_store_length(e, seq) < 0)	return -1;
		oid_list += l+1;
	}

	if (encode_store_length(e, oid_sequence) < 0)	return -1;
	if (encode_store_length(e, pdu) < 0)	return -1;
	if (encode_store_length(e, packet_sequence) < 0)	return -1;
	return 0;
}

int
start_snmp_get_packet(struct packet_builder *pb, int version, const char *community,
					  unsigned request_id)
{
	unsigned char *packet_buf;
	struct encode *e;

	bzero(pb, sizeof(*pb));
	packet_buf = malloc(65000);
	if (!packet_buf)
		croak(2, "start_get_request_packet: malloc(packet_buf)");
	pb->e = encode_init(packet_buf, 65000);
	e = &pb->e;

	SPACECHECK2;
	pb->packet_sequence = e->b;
   	pb->packet_sequence[0] = AT_SEQUENCE;
	EXTEND2;

	if (version < 0 || version > 1) {
		errno = EINVAL;
		return -1;
	}
	if (encode_integer((unsigned)version, e, 0) < 0)	return -1;
	if (encode_string(community, e) < 0)	return -1;

	SPACECHECK2;
	pb->pdu = e->b;
	pb->pdu[0] = PDU_GET_REQUEST;
	EXTEND2;

	if (encode_integer(request_id, e, 4) < 0)	return -1;
	pb->sid_offset = e->b - e->buf - 4;
	if (encode_integer(0, e, 0) < 0)	return -1; /* error-status */
	if (encode_integer(0, e, 0) < 0)	return -1; /* error-index */

	SPACECHECK2;
	pb->oid_sequence = e->b;
	pb->oid_sequence[0] = AT_SEQUENCE;
	EXTEND2;

	return 0;
}

int
add_encoded_oid_to_snmp_packet(struct packet_builder *pb, struct encode *oid)
{
	struct encode *e;
	unsigned char *seq;

	e = &pb->e;

	SPACECHECK2;
	seq = e->b;
	seq[0] = AT_SEQUENCE;
	EXTEND2;
	SPACECHECK(oid->len);
	memcpy(e->b, oid->buf, oid->len);
	EXTEND(oid->len);
	SPACECHECK2;
	e->b[0] = AT_NULL;
	e->b[1] = 0;
	EXTEND2;
	if (encode_store_length(e, seq) < 0)	return -1;
	return 0;
}

int
finalize_snmp_packet(struct packet_builder *pb, struct encode *encoded_packet)
{
	struct encode *e;
	int l;
	e = &pb->e;

	if ( (l = encode_store_length(e, pb->oid_sequence)) < 0)	return -1;
	pb->sid_offset += l;
	if (encode_store_length(e, pb->pdu) < 0)	return -1;
	if (encode_store_length(e, pb->packet_sequence) < 0)	return -1;
	*encoded_packet = encode_dup(e);
	free(e->buf);
	return pb->sid_offset;
}

int
encode_store_length(struct encode *e, unsigned char *s)
{
	int n = e->b - s - 2;

	/* assert(s >= e->buf); */
	/* assert(s + 2 <= e->b); */
	if (n <= 127) {
		s[1] = n & 0x7f;
		return 0;
	} else if ( n <= 255) {
		SPACECHECK(1);
		memmove(s+3, s+2, n);
		s[1] = 0x81;
		s[2] = n & 0xff;
		EXTEND(1);
		return 1;
	} else if ( n <= 65535) {
		SPACECHECK(2);
		memmove(s+4, s+2, n);
		s[1] = 0x82;
		s[2] = (n >> 8) & 0xff;
		s[3] = n & 0xff;
		EXTEND(2);
		return 2;
	} else {
		/* XXX larger sizes are possible */
		errno = EMSGSIZE;
		return -1;
	}
	return 0;
}

int
encode_string(const char *s, struct encode *e)
{
	int i = strlen(s);
	if (encode_type_len(AT_STRING, i, e) < 0)	return -1;
	if (e->len + i > e->max_len) {
		errno = EMSGSIZE;
		return -1;
	}
	memmove(e->b, s, i);
	e->b   += i;
	e->len += i;
	return 0;
}

int
encode_integer(unsigned i, struct encode *e, int force_size)
{
	int l;
	if (i <= 255)
		l = 1;
	else if (i <= 65535)
		l = 2;
	else if (i <= 16777215)
		l = 3;
	else if (i < 4294967295u)
		l = 4;
	else {
		errno = ERANGE;
		return -1;
	}
	if (force_size)
		l = force_size;
	if (encode_type_len(AT_INTEGER, l, e) < 0) return -1;
	SPACECHECK(l);
	switch (l) {
	case 4:
		e->b[l-4] = (i >> 24) & 0xff;
	case 3:
		e->b[l-3] = (i >> 16) & 0xff;
	case 2:
		e->b[l-2] = (i >> 8) & 0xff;
	case 1:
		e->b[l-1] = i & 0xff;
	}
	EXTEND(l);
	return 0;
}

int
encode_type_len(unsigned char type, unsigned i, struct encode *e)
{
	int l;
	if (i <= 127) {
		l = 2;
		SPACECHECK(l);
		e->b[1] = i & 0x7f;
	} else if (i <= 255) {
		l = 3;
		SPACECHECK(l);
		e->b[1] = 0x81;
		e->b[2] = i & 0xff;
	} else if (i <= 65535) {
		l = 4;
		SPACECHECK(l);
		e->b[1] = 0x82;
		e->b[2] = (i >> 8) & 0xff;
		e->b[3] = i & 0xff;
	} else if (i <= 16777215) {
		l = 5;
		SPACECHECK(l);
		e->b[1] = 0x83;
		e->b[2] = (i >> 16) & 0xff;
		e->b[3] = (i >> 8) & 0xff;
		e->b[4] = i & 0xff;
	} else if (i <= 4294967295u) {
		l = 6;
		SPACECHECK(l);
		e->b[1] = 0x83;
		e->b[2] = (i >> 24) & 0xff;
		e->b[3] = (i >> 16) & 0xff;
		e->b[4] = (i >> 8) & 0xff;
		e->b[5] = i & 0xff;
	} else {
		errno = ERANGE;
		return -1;
	}
	e->b[0] = type;
	EXTEND(l);
	return 0;
}

unsigned char *
decode_string_oid(unsigned char *s, int l, char *buf, int buf_size)
{
	int n, n_bytes, printed;
	unsigned x, x2 = 0;
	int first = 1;

	if (l < 1 || *s != AT_OID) {
		errno = EINVAL;
		return NULL;
	}
	s++;  l--;
	if (l < 1) {
		errno = EINVAL;
		return NULL;
	}
	n = *s;
	s++;  l--;
	if (n <= 127) {
		/* ok */;
	} else if (n == 0x81 && l >= 1) {
		n = *s;
		s++;  l--;
	} else if (n == 0x82 && l >= 2) {
		n = *s * 256;
		s++;  l--;
		n += *s;
		s++;  l--;
	} else {
		errno = EINVAL;
		return NULL;
	}
	if (n > l) {
		errno = EINVAL;
		return NULL;
	}

	while (l > 0) {
		x = 0; n_bytes = 0;
		while (*s >= 0x80 && l > 0) {
			x <<= 7;
			x |= *s & 0x7f;
			s++;  l--;
			n_bytes++;
		}
		if (l <= 0) {
			errno = EINVAL;
			return NULL;
		}
		x <<= 7;
		x |= *s & 0x7f;
		s++;  l--;
		if (n_bytes > 3) {
			errno = EINVAL;
			return NULL;
		}

		if (first) {
			x2 = x % 40;
			x /= 40;
			goto print_number;
second_number:
			x = x2;
			first = 0;
		}
print_number:
		if (!first && buf_size >= 1) {
			*buf++ = '.';
		}
		// XXX we probably want to replace snprintf() with something faster
		if ( (printed = snprintf(buf, buf_size, "%u", x)) >= buf_size) {
			errno = EMSGSIZE;
			return NULL;
		}
		buf += printed;
		buf_size -= printed;
		if (first)	goto second_number;
	}
	if (buf_size >= 1) {
		*buf = '\0';
		return s;
	}

	errno = EMSGSIZE;
	return NULL;
}

int
encode_string_oid(const char *oid, int oid_len, struct encode *e)
{
	const char *o;
	int l = 0;
	unsigned char *s = e->b;
	unsigned n;
	unsigned n2 = 0;
	const char *oend;

	if (oid_len < 0)
		oid_len = strlen(oid);
	oend = oid + oid_len;

	if (e->len + 2 > e->max_len) {
		errno = EMSGSIZE;
		return -1;
	}
	*s++ = AT_OID;
	s++;
	l += 2;

	o = oid;
	OENDCHECK;
	if (*o == '.') o++;

	n = 0;
	OENDCHECK;
	while (isdigit(*o)) {
		n = 10*n + *o++ - '0';
		OENDCHECK;
	}
	if (*o++ != '.') {
		errno = EINVAL;
		return -1;
	}
	OENDCHECK;
	while (isdigit(*o) && o < oend) {
		n2 = 10*n2 + *o++ - '0';
	}
	if (n2 >= 40) {
		errno = EINVAL;
		return -1;
	}
	n = 40*n + n2;

	while (1) {
		if (n > MAX_OID) {
			errno = EINVAL;
			return -1;
		}
		if (n <= 127) {
			if (e->len + l + 1 > e->max_len) {
				errno = EMSGSIZE;
				return -1;
			}
			*s++ = n;
			l++;
		} else if (n <= 16383) {
			if (e->len + l + 2 > e->max_len) {
				errno = EMSGSIZE;
				return -1;
			}
			*s++ = 0x80 | (n >> 7);
			*s++ = n & 0x7f;
			l += 2;
		} else if (n <= 2097151) {
			if (e->len + l + 3 > e->max_len) {
				errno = EMSGSIZE;
				return -1;
			}
			*s++ = 0x80 | (n >> 14);
			*s++ = 0x80 | ((n >> 7) & 0x7f);
			*s++ = n & 0x7f;
			l += 3;
		} else {
			if (e->len + l + 4 > e->max_len) {
				errno = EMSGSIZE;
				return -1;
			}
			*s++ = 0x80 | (n >> 21);
			*s++ = 0x80 | ((n >> 14) & 0x7f);
			*s++ = 0x80 | ((n >> 7) & 0x7f);
			*s++ = n & 0x7f;
			l += 4;
		}
		if (o == oend)  break;
		if (*o++ != '.') {
			errno = EINVAL;
			return -1;
		}
		n = 0;
		OENDCHECK;
		while (isdigit(*o) && o < oend) {
			n = 10*n + *o++ - '0';
		}
	}
	n = l - 2;
	if (n <= 127) {
		e->b[1] = n & 0x7f;
		e->b   += l;
		e->len += l;
	} else if ( n <= 255) {
		if (e->len + l + 1 > e->max_len) {
			errno = EMSGSIZE;
			return -1;
		}
		memmove(e->b+3, e->b+2, n);
		e->b[1] = 0x81;
		e->b[2] = n & 0xff;
		e->b   += l+1;
		e->len += l+1;
	} else if ( n <= 65535) {
		if (e->len + l + 2 > e->max_len) {
			errno = EMSGSIZE;
			return -1;
		}
		memmove(e->b+4, e->b+2, n);
		e->b[1] = 0x82;
		e->b[2] = (n >> 8) & 0xff;
		e->b[3] = n & 0xff;
		e->b   += l+2;
		e->len += l+2;
	} else {
		errno = EMSGSIZE;
		return -1;
	}
	return o-oid;
}

void
encode_dump(FILE *f, struct encode *e)
{
	dump_buf(f, e->buf, e->len);
}
