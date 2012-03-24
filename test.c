#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#define AT_INTEGER  2
#define AT_STRING   4
#define AT_OID      6
#define AT_SEQUENCE 0x30

#define MAX_OID 268435455  /* 2^28-1 to fit into 4 bytes */

#define PDU_GET_REQUEST 0xa0

struct encode
{
	unsigned char *buf;
	unsigned char *b;
	int len;
	int max_len;
};

extern int encode_type_len(unsigned char type, unsigned i, struct encode *e);
extern int encode_integer(unsigned i, struct encode *e);
extern int encode_string(const char *s, struct encode *e);

struct encode encode_init(void *buf, int size)
{
	struct encode e;
	e.buf = e.b = buf;
	e.len = 0;
	e.max_len = size;
	return e;
}

int
build_get_request_packet(int version, const char *community,
						 const char *oid_list,
						 unsigned request_id, struct encode *e)
{
	unsigned char *packet_sequence = e->b;
	unsigned char *pdu;

	if (e->len + 2 > e->max_len) {
		errno = EMSGSIZE;
		return -1;
	}
	packet_sequence[0] = AT_SEQUENCE;
	e->len += 2;
	e->b   += 2;
	if (version < 0 || version > 1) {
		errno = EINVAL;
		return -1;
	}
	if (encode_integer((unsigned)version, e) < 0)	return -1;
	if (encode_string(community, e) < 0)	return -1;
	if (e->len + 2 > e->max_len) {
		errno = EMSGSIZE;
		return -1;
	}
	pdu = e->b;
	pdu[0] = PDU_GET_REQUEST;
	e->len += 2;
	e->b   += 2;
	if (encode_integer(request_id, e) < 0)	return -1;
	if (encode_integer(0, e) < 0)	return -1; /* error-status */
	if (encode_integer(0, e) < 0)	return -1; /* error-index */
	// XXX
	// sequence of oid-values
	//    sequence
	//       oid
	//       value
	//    adjust length
	// adjust length
	// adjust PDU length
	// adjust packet sequence length
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
encode_integer(unsigned i, struct encode *e)
{
	return encode_type_len(AT_INTEGER, i, e);
}

int
encode_type_len(unsigned char type, unsigned i, struct encode *e)
{
	int l;
	if (i <= 127) {
		l = 2;
		if (e->len + l > e->max_len) {
			errno = EMSGSIZE;
			return -1;
		}
		e->b[1] = i & 0x7f;
	} else if (i <= 255) {
		l = 3;
		if (e->len + l > e->max_len) {
			errno = EMSGSIZE;
			return -1;
		}
		e->b[1] = 0x81;
		e->b[2] = i & 0xff;
	} else if (i <= 65535) {
		l = 4;
		if (e->len + l > e->max_len) {
			errno = EMSGSIZE;
			return -1;
		}
		e->b[1] = 0x82;
		e->b[2] = (i >> 8) & 0xff;
		e->b[3] = i & 0xff;
	} else if (i <= 16777215) {
		l = 5;
		if (e->len + l > e->max_len) {
			errno = EMSGSIZE;
			return -1;
		}
		e->b[1] = 0x83;
		e->b[2] = (i >> 16) & 0xff;
		e->b[3] = (i >> 8) & 0xff;
		e->b[4] = i & 0xff;
	} else if (i <= 4294967295u) {
		l = 6;
		if (e->len + l > e->max_len) {
			errno = EMSGSIZE;
			return -1;
		}
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
	e->b   += l;
	e->len += l;
	return 0;
}

int
encode_string_oid(const char *oid, struct encode *e)
{
	int l = 0;
	unsigned char *s = e->b;
	unsigned n;
	unsigned n2 = 0;

	if (e->len + 2 > e->max_len) {
		errno = EMSGSIZE;
		return -1;
	}
	*s++ = AT_OID;
	s++;
	l += 2;

	if (*oid == '.') oid++;

	n = 0;
	while (isdigit(*oid)) {
		n = 10*n + *oid++ - '0';
	}
	if (*oid++ != '.') {
		errno = EINVAL;
		return -1;
	}
	while (isdigit(*oid)) {
		n2 = 10*n2 + *oid++ - '0';
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
		if (*oid == 0)	break;
		if (*oid++ != '.') {
			errno = EINVAL;
			return -1;
		}
		n = 0;
		while (isdigit(*oid)) {
			n = 10*n + *oid++ - '0';
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
	return 0;
}

void
encode_dump(FILE *f, struct encode *e)
{
	unsigned char *s = e->buf;
	int i;

	for (i = 0; i < e->len; i++) {
		fprintf(f, "%02x", (unsigned)*s++);
	}
	fprintf(f, "\n");
}

int
test(const char *oid, const char *res, int len)
{
	char *buf = malloc(len + 20);
	struct encode e = encode_init(buf, len + 20);

	buf[len] = '\x55';
	if (encode_string_oid(oid, &e) < 0) {
		fprintf(stderr, "encode_string_oid: unexpected failure, oid %s\n", oid);
		free(buf);
		return 0;
	}
	if (e.len != len) {
		fprintf(stderr, "encode_string_oid: unexpected length (%d != %d), oid %s\n", e.len, len, oid);
		free(buf);
		return 0;
	}
	if (buf[len] != '\x55') {
		fprintf(stderr, "encode_string_oid: buffer corruped, oid %s\n", oid);
		free(buf);
		return 0;
	}
	if (memcmp(buf, res, len) != 0) {
		fprintf(stderr, "encode_string_oid: unexpected buffer content, oid %s\n", oid);
		free(buf);
		return 0;
	}
	e = encode_init(buf, len);
	if (encode_string_oid(oid, &e) < 0) {
		fprintf(stderr, "encode_string_oid: unexpected failure with just enough buffer space, oid %s\n", oid);
		free(buf);
		return 0;
	}
	e = encode_init(buf, len-1);
	if (encode_string_oid(oid, &e) == 0) {
		fprintf(stderr, "encode_string_oid: unexpected success with slightly not enough buffer space, oid %s\n", oid);
		free(buf);
		return 0;
	}
	free(buf);
	return 1;
}

int
main(void)
{
	int success = 0;
	success += test("1.3.6.1.2.1.2.2.1.2.1001", "\x06\x0b\x2b\x06\x01\x02\x01\x02\x02\x01\x02\x87\x69", 13);
	success += test(".1.3.6.1.2.1.2.2.1.2.25", "\x06\x0a\x2b\x06\x01\x02\x01\x02\x02\x01\x02\x19", 12);
	success += test("1.3.6.1.4.1.2636.3.5.2.1.5.33.118.54.95.73.78.70.82.65.95.67.79.78.78.69.67.84.95.86.49.45.103.101.45.50.47.49.47.48.46.51.56.45.105.81.118.54.95.73.78.70.82.65.95.68.69.70.95.73.67.77.80.95.73.78.70.79.82.77.65.84.73.79.78.65.76.45.118.54.95.73.78.70.82.65.95.67.79.78.78.69.67.84.95.73.67.77.80.95.73.78.70.79.82.77.65.84.73.79.78.65.76.45.103.101.45.50.47.49.47.48.46.51.56.45.105.3",
					"\x06\x81\x81\x2b\x06\x01\x04\x01\x94\x4c\x03\x05\x02\x01\x05\x21\x76\x36\x5f\x49\x4e\x46\x52\x41\x5f\x43\x4f\x4e\x4e\x45\x43\x54\x5f\x56\x31\x2d\x67\x65\x2d\x32\x2f\x31\x2f\x30\x2e\x33\x38\x2d\x69\x51\x76\x36\x5f\x49\x4e\x46\x52\x41\x5f\x44\x45\x46\x5f\x49\x43\x4d\x50\x5f\x49\x4e\x46\x4f\x52\x4d\x41\x54\x49\x4f\x4e\x41\x4c\x2d\x76\x36\x5f\x49\x4e\x46\x52\x41\x5f\x43\x4f\x4e\x4e\x45\x43\x54\x5f\x49\x43\x4d\x50\x5f\x49\x4e\x46\x4f\x52\x4d\x41\x54\x49\x4f\x4e\x41\x4c\x2d\x67\x65\x2d\x32\x2f\x31\x2f\x30\x2e\x33\x38\x2d\x69\x03",
					132);
	fprintf(stderr, "%d of %d tests passed succesfully\n", success, 3);
	return 0;
}

