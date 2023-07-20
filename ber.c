/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2013, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

#define SPACECHECK(bytes) if (e->len + (bytes) > e->max_len) { errno = EMSGSIZE; return -1; }
#define SPACECHECK2 SPACECHECK(2)
#define EXTEND(bytes) { int sz = (bytes); e->len += sz; e->b += sz; }
#define EXTEND2 EXTEND(2)
#define OENDCHECK if (o >= oend) { errno = EINVAL; return -1; }

static unsigned char BUF_NULL[] = "\x05";
struct ber BER_NULL = { BUF_NULL, BUF_NULL+2, 2, 2 };
static unsigned char BUF_TIMEOUT[] = "\x8a";
struct ber BER_TIMEOUT = { BUF_TIMEOUT, BUF_TIMEOUT+2, 2, 2 };
static unsigned char BUF_MISSING[] = "\x8b";
struct ber BER_MISSING = { BUF_MISSING, BUF_MISSING+2, 2, 2 };
static unsigned char BUF_IGNORED[] = "\x8e";
struct ber BER_IGNORED = { BUF_IGNORED, BUF_IGNORED+2, 2, 2 };
static unsigned char BUF_NON_INCREASING[] = "\x8f";
struct ber BER_NON_INCREASING = { BUF_NON_INCREASING, BUF_NON_INCREASING+2, 2, 2 };

int
ber_is_null(struct ber *ber)
{
	return ber->len >= 2 && ber->buf[0] == 5 && ber->buf[1] == 0;
}

struct ber ber_init(void *buf, int size)
{
	struct ber e;
	e.buf = e.b = buf;
	e.len = 0;
	e.max_len = size;
	return e;
}

struct ber ber_dup(struct ber *eo)
{
	char *buf = malloc(eo->len);
	struct ber en;

	if (!buf)
		croak(2, "ber_dup: malloc(buf(%d))", eo->len);
	en = ber_init(buf, eo->len);
	memcpy(buf, eo->buf, eo->len);
	en.len = eo->len;
	en.b += eo->len;
	return en;
}

struct ber ber_rewind(struct ber o)
{
	o.b = o.buf;
	o.len = 0;
	return o;
}

int
ber_equal(struct ber *b1, struct ber *b2)
{
	if (b1->len != b2->len)
		return 0;
	return memcmp(b1->buf, b2->buf, b1->len) == 0;
}

struct ber
ber_error_status(int error_status)
{
	char error_string[40];
	char buf[64];
	struct ber b;

	switch (error_status) {
	case 0:
		strcpy(error_string, "noError");
		break;
	case 1:
		strcpy(error_string, "tooBig");
		break;
	case 2:
		strcpy(error_string, "noSuchName");
		break;
	case 3:
		strcpy(error_string, "badValue");
		break;
	case 4:
		strcpy(error_string, "readOnly");
		break;
	case 5:
		strcpy(error_string, "genErr");
		break;
	case 6:
		strcpy(error_string, "noAccess");
		break;
	case 7:
		strcpy(error_string, "wrongType");
		break;
	case 8:
		strcpy(error_string, "wrongLength");
		break;
	case 9:
		strcpy(error_string, "wrongEncoding");
		break;
	case 10:
		strcpy(error_string, "wrongValue");
		break;
	case 11:
		strcpy(error_string, "noCreation");
		break;
	case 12:
		strcpy(error_string, "inconsistentValue");
		break;
	case 13:
		strcpy(error_string, "resourceUnavailable");
		break;
	case 14:
		strcpy(error_string, "commitFailed");
		break;
	case 15:
		strcpy(error_string, "undoFailed");
		break;
	case 16:
		strcpy(error_string, "authorizationError");
		break;
	case 17:
		strcpy(error_string, "notWritable");
		break;
	case 18:
		strcpy(error_string, "inconsistentName");
		break;
	default:
		sprintf(error_string, "error-status %d", error_status);
	}
	b = ber_init(buf, 64);
	encode_string(error_string, &b);
	b.buf[0] = VAL_STRING_ERROR;
	return ber_rewind(ber_dup(&b));
}

int
build_get_request_packet(int version, const char *community,
						 const char *oid_list,
						 unsigned request_id, struct ber *e)
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
add_encoded_oid_to_snmp_packet(struct packet_builder *pb, struct ber *oid)
{
	struct ber *e;
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

/// @brief Initialize SNMP packet builder structure pb with necessary fields.
/// @param pb 			packet builder structure to work with
/// @param version 		SNMP version to use (0 = SNMPv1, 1 = SNMPv2c, 3 = SNMPv3)
/// @param request_id   a request id
/// @param v3 		    a pointer to snmpv3options structure;  must not be NULL if version == 3
/// @param community    an SNMP community string;  must not be NULL if version != 3
/// @return 0 for success, -1 for failure, in which case errno is set
int
start_snmp_packet(struct packet_builder* pb,
                  int version,
                  unsigned request_id,
                  const struct snmpv3info* v3,
                  const char* community)
{
	unsigned char *packet_buf;
	struct ber *e;

	memset(pb, 0, sizeof(*pb));
	packet_buf = malloc(65000);
	if (!packet_buf)
		croak(2, "start_snmp_packet: malloc(packet_buf)");
	pb->e = ber_init(packet_buf, 65000);
	e = &pb->e;

	SPACECHECK2;
	pb->packet_sequence = e->b;
   	pb->packet_sequence[0] = AT_SEQUENCE;
	EXTEND2;

	if (version != 0 && version != 1 && version != 3) {
		errno = EINVAL;
		return -1;
	}
	if (encode_integer((unsigned)version, e, 0) < 0)	return -1;

	if (version == 3) {
		int l;
		unsigned char *gdata, *sec_params_string, *sec_params_seq;
		unsigned char msg_flags = V3F_AUTHENTICATED | V3F_ENCRYPTED | V3F_REPORTABLE;
		unsigned int msg_security_model = 3;  // HACK authFlag | privFlag
		unsigned char zeroes[32];

		pb->pi.v3 = true;
		memset(zeroes, 0, 32);

		SPACECHECK2;
		gdata = e->b;
		gdata[0] = AT_SEQUENCE;
		EXTEND2;

		/* We just set msgID to be the same as request-id in the PDU */
		if (encode_integer(request_id, e, 0) < 0)	return -1; // XXX always 4 bytes?
		pb->pi.sid_offset = e->b - e->buf - 4;
		if (encode_integer(v3->msg_max_size, e, 2) < 0)	return -1;
		if (encode_bytes(&msg_flags, 1, e) < 0)	return -1;
		if (encode_integer(msg_security_model, e, 0) < 0)	return -1;

		l = encode_store_length(e, gdata);
		if (l < 0)	return -1;
		pb->pi.sid_offset += l;

		SPACECHECK2;
		sec_params_string = e->b;
		sec_params_string[0] = AT_STRING;
		EXTEND2;

		SPACECHECK2;
		sec_params_seq = e->b;
		sec_params_seq[0] = AT_SEQUENCE;
		EXTEND2;

		if (encode_bytes(v3->engine_id, v3->engine_id_len, e) < 0)	return -1;

		if (encode_integer(v3->engine_boots, e, 0) < 0)	return -1;
		if (encode_integer(v3->engine_time, e, 0) < 0)	return -1;

		if (encode_string(v3->username, e) < 0)	return -1;
		pb->pi.authp_offset = e->b - e->buf + 2;
		if (encode_bytes(zeroes, 12, e) < 0)	return -1;
		pb->pi.privp_offset = e->b - e->buf + 2;
		if (encode_bytes(zeroes, 8, e) < 0)	return -1;

		l = encode_store_length(e, sec_params_seq);
		if (l < 0)	return -1;
		pb->pi.authp_offset += l;
		pb->pi.privp_offset += l;

		l = encode_store_length(e, sec_params_string);
		if (l < 0)	return -1;
		pb->pi.authp_offset += l;
		pb->pi.privp_offset += l;

		SPACECHECK2;
		pb->encrypted_pdu = e->b;
		pb->encrypted_pdu[0] = AT_STRING;
		EXTEND2;

		SPACECHECK2;
		pb->decrypted_scoped_pdu = e->b;
		pb->decrypted_scoped_pdu[0] = AT_SEQUENCE;
		EXTEND2;

		if (encode_bytes(v3->engine_id, v3->engine_id_len, e) < 0)	return -1;
		if (encode_bytes(zeroes, 0, e) < 0)	return -1;

	} else {
		if (encode_string(community, e) < 0)	return -1;
	}

	SPACECHECK2;
	pb->pdu = e->b;
	pb->pdu[0] = PDU_GET_REQUEST;
	EXTEND2;

	if (encode_integer(request_id, e, 4) < 0)	return -1;
	if (version != 3)
		pb->pi.sid_offset = e->b - e->buf - 4;
	if (encode_integer(0, e, 0) < 0)	return -1; /* error-status */
	if (encode_integer(0, e, 0) < 0)	return -1; /* error-index */
	pb->max_repetitions  = e->b - 1;

	SPACECHECK2;
	pb->oid_sequence = e->b;
	pb->oid_sequence[0] = AT_SEQUENCE;
	EXTEND2;

	return 0;
}

int
finalize_snmp_packet(struct packet_builder* pb,
                     struct ber* out_encoded_packet,
					 const struct snmpv3info* v3,
                     struct packet_info* out_pi,
                     unsigned char type,
                     int max_repetitions)
{
	struct ber *e;
	int l;
	e = &pb->e;

	if (type == PDU_GET_BULK_REQUEST) {
		if (max_repetitions <= 0)
			max_repetitions = 10;
		if (max_repetitions > 255)
			max_repetitions = 255;
		pb->max_repetitions[0] = (unsigned char)max_repetitions;
	}

	l = encode_store_length(e, pb->oid_sequence);
	if (l < 0)	return -1;

	l = encode_store_length(e, pb->pdu);
	if (l < 0)	return -1;
	pb->pdu[0] = type;

	if (!pb->pi.v3)
		pb->pi.sid_offset += l;

	if (pb->decrypted_scoped_pdu) {
		l = encode_store_length(e, pb->decrypted_scoped_pdu);
		if (l < 0)	return -1;
		l = encrypt_in_place(pb->decrypted_scoped_pdu, e->b - pb->decrypted_scoped_pdu, e->buf + pb->pi.privp_offset, v3);
		if (l < 0)	return -1;
	}

	if (pb->encrypted_pdu) {
		l = encode_store_length(e, pb->encrypted_pdu);
		if (l < 0)	return -1;
	}

	l = encode_store_length(e, pb->packet_sequence);
	if (l < 0)	return -1;
	pb->pi.sid_offset += l;
    pb->pi.authp_offset += l;
    pb->pi.privp_offset += l;

	// authenticate
	if (pb->pi.v3 && v3) {
		fprintf(stderr, "Before hmac_message:\n");
    	ber_dump(stderr, e);
    	if (hmac_message(v3,
                      	 e->buf + pb->pi.authp_offset,
                     	 12,
                         e->buf,
                         e->len,
                         e->buf + pb->pi.authp_offset) < 0) {
			return -1;
		}
		fprintf(stderr, "After hmac_message:\n");
        ber_dump(stderr, e);
        fprintf(stderr, "\n");
{
FILE *ff = fopen("/tmp/finalized-v3.bin", "w");
//ber_dump(ff, e);
fwrite(e->buf, 1, e->len, ff);
fclose(ff);
//exit(1);
}

	}

	*out_encoded_packet = ber_dup(e);
	*out_pi = pb->pi;
	free(e->buf);
	return pb->pi.sid_offset;
}

/// @brief Stores actual length of a composite starting at s and ending at e->b, moving memory block if needed;  think of it as a finalizer for the composite.
/// @param e the ber structure
/// @param s start of a composite
/// @return -1 on failure, adjustment size (0,1,2) on success
int
encode_store_length(struct ber *e, unsigned char *s)
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

/// @brief Encodes a null-terminated string s as an OCTET STRING into a ber structure e
/// @param s string
/// @param e ber structure pointer
/// @return 0 on success, -1 on failure (sets errno)
int
encode_string(const char *s, struct ber *e)
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

/// @brief Encodes n bytes at p as an OCTET STRING into a ber structure e
/// @param p bytes pointer
/// @param n number of bytes to encode
/// @param e ber structure pointer
/// @return 0 on success, -1 on failure (sets errno)
int
encode_bytes(const unsigned char *p, int n, struct ber *e)
{
	if (encode_type_len(AT_STRING, n, e) < 0)	return -1;
	if (e->len + n > e->max_len) {
		errno = EMSGSIZE;
		return -1;
	}
	memmove(e->b, p, n);
	e->b   += n;
	e->len += n;
	return 0;
}

int
encode_integer(unsigned i, struct ber *e, int force_size)
{
	int l;
	if (i <= 255)
		l = 1;
	else if (i <= 65535)
		l = 2;
	else if (i <= 16777215)
		l = 3;
	else if (i <= 4294967295u)
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
decode_composite(struct ber *e, unsigned char comp_type, int *composite_end_pos)
{
	unsigned char t;
	unsigned len;

	if (decode_type_len(e, &t, &len) < 0)	return -1;
	if (t != comp_type) {
		errno = EINVAL;
		return -1;
	}
	if (len + (unsigned)e->len > INT_MAX) {
		errno = ERANGE;
		return -1;
	}
	/* SPACECHECK(len);  -- done already by decode_type_len() */
	if (composite_end_pos)
		*composite_end_pos = ((int)len) + e->len;
	return 0;
}

int
decode_ipv4_address(struct ber *e, int l, struct in_addr *ip)
{
	unsigned char t;
	unsigned len;
	unsigned int_ip;
	if (l < 0) {
		if (decode_type_len(e, &t, &len) < 0)	return -1;
		if (t != AT_IP_ADDRESS) {
			errno = EINVAL;
			return -1;
		}
		if (len > INT_MAX) {
			errno = ERANGE;
			return -1;
		}
		l = (int)len;
	}
	if (decode_integer(e, l, &int_ip) < 0)
		return -1;
	ip->s_addr = htonl(int_ip);
	return 0;
}

int
decode_octets(struct ber *e, unsigned char *s, unsigned s_size, unsigned *s_len)
{
	unsigned char t;
    if (decode_type_len(e, &t, s_len) < 0) return -1;
	if (t != AT_STRING) {
		errno = EINVAL;
		return -1;
	}
	if (*s_len > s_size) {
		errno = EMSGSIZE;
		return -1;
	}
	memcpy(s, e->b, *s_len);

    e->b += *s_len;
    e->len += *s_len;
	return 0;
}

// just like decode_octets but expects space for nul byte at the end and adds said nul byte
int
decode_string(struct ber *e, unsigned char *s, unsigned s_size, unsigned *s_len)
{
	unsigned char t;
    if (decode_type_len(e, &t, s_len) < 0) return -1;
	if (t != AT_STRING) {
		errno = EINVAL;
		return -1;
	}
	if (*s_len >= s_size) {
		errno = EMSGSIZE;
		return -1;
	}
	memcpy(s, e->b, *s_len);
	s[*s_len] = 0;

    e->b += *s_len;
    e->len += *s_len;
	return 0;
}

int
decode_integer(struct ber *e, int l, unsigned *value)
{
	unsigned char t;
	unsigned len;
	if (l < 0) {
		if (decode_type_len(e, &t, &len) < 0)	return -1;
		if (t != AT_INTEGER) {
			errno = EINVAL;
			return -1;
		}
		if (len > INT_MAX) {
			errno = ERANGE;
			return -1;
		}
		l = (int)len;
	}
	SPACECHECK(l);
	if (!value) {
		EXTEND(l);
		return 0;
	}
	*value = 0;
	while (l) {
		*value = *value << 8  | e->b[0];
		EXTEND(1);
		l--;
	}
	return 0;
}

int
decode_timeticks(struct ber *e, int l, unsigned long long *value)
{
	unsigned char t;
	unsigned len;
	if (l < 0) {
		if (decode_type_len(e, &t, &len) < 0)	return -1;
		if (t != AT_TIMETICKS) {
			errno = EINVAL;
			return -1;
		}
		if (len > INT_MAX) {
			errno = ERANGE;
			return -1;
		}
		l = (int)len;
	}
	return decode_counter64(e, l, value);
}

int
decode_counter64(struct ber *e, int l, unsigned long long *value)
{
	unsigned char t;
	unsigned len;
	if (l < 0) {
		if (decode_type_len(e, &t, &len) < 0)	return -1;
		if (t != AT_COUNTER64) {
			errno = EINVAL;
			return -1;
		}
		if (len > INT_MAX) {
			errno = ERANGE;
			return -1;
		}
		l = (int)len;
	}
	SPACECHECK(l);
	if (!value) {
		EXTEND(l);
		return 0;
	}
	*value = 0;
	while (l) {
		*value = *value << 8  | e->b[0];
		EXTEND(1);
		l--;
	}
	return 0;
}

int
decode_oid(struct ber *e, struct ber *dst)
{
	unsigned char t;
	unsigned len;

	if (dst)
		dst->buf = e->b;
	if (decode_type_len(e, &t, &len) < 0)	return -1;
	if (t != AT_OID) {
		errno = EINVAL;
		return -1;
	}
	EXTEND(len);
	if (dst) {
		dst->max_len = dst->len = e->b - dst->buf;
		dst->b = e->b;
	}
	return 0;
}

int
decode_any(struct ber *e, struct ber *dst)
{
	unsigned char t;
	unsigned len;

	if (dst)
		dst->buf = e->b;
	if (decode_type_len(e, &t, &len) < 0)	return -1;
	EXTEND(len);
	if (dst) {
		dst->max_len = dst->len = e->b - dst->buf;
		dst->b = e->b;
	}
	return 0;
}

int
decode_type_len(struct ber *e, unsigned char *type, unsigned *len)
{
	unsigned l;

	SPACECHECK(2);
	*type = e->b[0];
	EXTEND(1);
	l = e->b[0];
	EXTEND(1);
	if (l <= 127) {
		/* do nothing */
	} else if (l == 0x81) {
		SPACECHECK(1);
		l = e->b[0];
		EXTEND(1);
	} else if (l == 0x82) {
		SPACECHECK(2);
		l = (e->b[0] << 8)  | e->b[1];
		EXTEND(2);
	} else if (l == 0x83) {
		SPACECHECK(3);
		l = ((e->b[0] << 8)  | e->b[1]) << 8  | e->b[2];
		EXTEND(3);
	} else if (l == 0x84) {
		SPACECHECK(4);
		l = (((e->b[0] << 8)  | e->b[1]) << 8  | e->b[2]) << 8  | e->b[3];
		EXTEND(4);
	} else {
		errno = ERANGE;
		return -1;
	}
	SPACECHECK(l);
	*len = l;
	return 0;
}

int
encode_type_len(unsigned char type, unsigned i, struct ber *e)
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
		e->b[1] = 0x84;
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

	l = n; /* so that garbage at the end is ok */
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
		if (n_bytes > 4) {
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
			buf_size--;
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
encode_string_oid(const char *oid, int oid_len, struct ber *e)
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
		} else if (n <= 268435456) {
			if (e->len + l + 4 > e->max_len) {
				errno = EMSGSIZE;
				return -1;
			}
			*s++ = 0x80 | (n >> 21);
			*s++ = 0x80 | ((n >> 14) & 0x7f);
			*s++ = 0x80 | ((n >> 7) & 0x7f);
			*s++ = n & 0x7f;
			l += 4;
		} else {
			if (e->len + l + 5 > e->max_len) {
				errno = EMSGSIZE;
				return -1;
			}
			*s++ = 0x80 | (n >> 28);
			*s++ = 0x80 | ((n >> 21) & 0x7f);
			*s++ = 0x80 | ((n >> 14) & 0x7f);
			*s++ = 0x80 | ((n >> 7) & 0x7f);
			*s++ = n & 0x7f;
			l += 5;
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
ber_dump(FILE *f, struct ber *e)
{
	dump_buf(f, e->buf, e->len);
}

int
oid_belongs_to_table(struct ber *oo, struct ber *tt)
{
	unsigned char otype, ttype;
	unsigned olen, tlen;
	struct ber o = ber_init(oo->buf, oo->max_len);
	struct ber t = ber_init(tt->buf, tt->max_len);

	if (decode_type_len(&o, &otype, &olen) < 0)	return 0;
	if (decode_type_len(&t, &ttype, &tlen) < 0)	return 0;

	if (olen <= tlen) return 0;
	if (otype != AT_OID || ttype != AT_OID) return 0;

	if (memcmp(o.b, t.b, tlen) != 0) return 0;
	return 1;
}

#define PROBLEM (-9999)
int
oid_compare(struct ber *aa, struct ber *bb)
{
	unsigned char atype, btype;
	unsigned alen, blen;
	struct ber a = ber_init(aa->buf, aa->max_len);
	struct ber b = ber_init(bb->buf, bb->max_len);
	unsigned char *as, *bs;
	unsigned ax, bx, abytes, bbytes;

	if (decode_type_len(&a, &atype, &alen) < 0)	return PROBLEM;
	if (decode_type_len(&b, &btype, &blen) < 0)	return PROBLEM;
	if (atype != AT_OID || btype != AT_OID) return PROBLEM;

	as = a.b;
	bs = b.b;

	while (alen && blen) {
		ax = 0; abytes = 0;
		while (*as >= 0x80 && alen > 0) {
			ax <<= 7;
			ax |= *as & 0x7f;
			as++;  alen--;
			abytes++;
		}
		if (alen <= 0) {
			errno = EINVAL;
			return PROBLEM;
		}
		ax <<= 7;
		ax |= *as & 0x7f;
		as++;  alen--;
		if (abytes > 4) {
			errno = EINVAL;
			return PROBLEM;
		}

		bx = 0; bbytes = 0;
		while (*bs >= 0x80 && blen > 0) {
			bx <<= 7;
			bx |= *bs & 0x7f;
			bs++;  blen--;
			bbytes++;
		}
		if (blen <= 0) {
			errno = EINVAL;
			return PROBLEM;
		}
		bx <<= 7;
		bx |= *bs & 0x7f;
		bs++;  blen--;
		if (bbytes > 4) {
			errno = EINVAL;
			return PROBLEM;
		}

		if (ax < bx)
			return -1;
		else if (ax > bx)
			return 1;
	}
	if (alen)
		return 1;
	if (blen)
		return -1;
	return 0;
}

struct ber usmStatsNotInTimeWindows;
struct ber usmStatsWrongDigests;

int
populate_well_known_oids(void)
{
    char tmp_buf[2048];
    struct ber e;

    e = ber_init(tmp_buf, 2048);
    if (encode_string_oid("1.3.6.1.6.3.15.1.1.2.0", -1, &e) < 0) {
        return -1;
	}
	usmStatsNotInTimeWindows = ber_dup(&e);

    e = ber_init(tmp_buf, 2048);
    if (encode_string_oid("1.3.6.1.6.3.15.1.1.5.0", -1, &e) < 0) {
        return -1;
	}
	usmStatsWrongDigests = ber_dup(&e);

	return 0;
}