/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2014, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#ifndef _COMMON_H
#define _COMMON_H

#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#define __USE_XOPEN
#include <limits.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#if defined(__FreeBSD__) || defined(__APPLE__)
#include <sys/event.h>
#define WITH_KQUEUE 1
#endif
#if defined(__linux__)
#include <sys/epoll.h>
#define WITH_EPOLL 1
#endif

#include <Judy.h>
#include <msgpack.h>

#if MSGPACK_VERSION_MAJOR == 0 && MSGPACK_VERSION_MINOR < 6
#error libmsgpackc is too old, at least v0.6 needed
#endif

#include "bsdqueue.h"

#define RT_UNKNOWN   0
#define RT_SETOPT    1
#define RT_GETOPT    2
#define RT_INFO      3
#define RT_GET       4
#define RT_GETTABLE  5
#define RT_DEST_INFO 6

#define RT_REPLY  0x10           /* ORed with RT type */
#define RT_ERROR  0x20           /* ORed with RT type */

#define RI_TYPE          0
#define RI_CID           1

#define RI_GETOPT_IP     2
#define RI_GETOPT_PORT   3

#define RI_SETOPT_IP     2
#define RI_SETOPT_PORT   3
#define RI_SETOPT_OPT    4

#define RI_GET_IP        2
#define RI_GET_PORT      3
#define RI_GET_OIDS      4

#define RI_GETTABLE_IP   2
#define RI_GETTABLE_PORT 3
#define RI_GETTABLE_OID  4
#define RI_GETTABLE_MREP 5

#define RI_DEST_INFO_IP     2
#define RI_DEST_INFO_PORT   3

#define AT_INTEGER          2
#define AT_STRING           4
#define AT_NULL		        5
#define AT_OID              6
#define AT_SEQUENCE         0x30

#define AT_IP_ADDRESS       0x40
#define AT_COUNTER          0x41
#define AT_UNSIGNED         0x42
#define AT_TIMETICKS        0x43
#define AT_OPAQUE           0x44
#define AT_COUNTER64        0x46

#define AT_NO_SUCH_OBJECT   0x80
#define AT_NO_SUCH_INSTANCE 0x81
#define AT_END_OF_MIB_VIEW  0x82

#define PDU_GET_REQUEST      0xa0
#define PDU_GET_NEXT_REQUEST 0xa1
#define PDU_GET_RESPONSE     0xa2
#define PDU_SET_REQUEST      0xa3
#define PDU_TRAP             0xa4
#define PDU_GET_BULK_REQUEST 0xa5
#define PDU_INFORM_REQUEST   0xa6
#define PDU_SNMPV2_TRAP      0xa7
#define PDU_REPORT           0xa8

/* Our own "ASN" types, used internally */
#define VAL_TIMEOUT          0x8a
#define VAL_MISSING          0x8b
#define VAL_UNSUPPORTED      0x8c
#define VAL_DECODE_ERROR     0x8d
#define VAL_IGNORED          0x8e
#define VAL_NON_INCREASING   0x8f
#define VAL_STRING_ERROR     0x90

#define MAX_OID 4294967295u  /* 2^35-1 to fit into 5 bytes, but we limit that to 2^32-1 */

typedef void* JudyL;

struct program_stats
{
	int64_t	active_client_connections;
	int64_t total_client_connections;

	int64_t client_requests;
	int64_t invalid_requests;
	int64_t setopt_requests;
	int64_t getopt_requests;
	int64_t info_requests;
	int64_t get_requests;
	int64_t gettable_requests;
	int64_t dest_info_requests;

	int64_t snmp_sends;
	int64_t snmp_v1_sends;
	int64_t snmp_v2c_sends;
	int64_t snmp_v3_sends;
	int64_t snmp_retries;
	int64_t snmp_timeouts;
	int64_t udp_timeouts;
	int64_t good_snmp_responses;
	int64_t bad_snmp_responses;
	int64_t oids_non_increasing;
	int64_t oids_requested;
	int64_t oids_returned_from_snmp;
	int64_t oids_returned_to_client;
	int64_t oids_ignored;

	int64_t octets_received;
	int64_t octets_sent;

	int64_t active_timers_sec;
	int64_t active_timers_usec;
	int64_t total_timers_sec;
	int64_t total_timers_usec;
	int64_t uptime;  /* in msec */
	int64_t program_version; /* such as 2013072200 */

	int64_t active_sid_infos;
	int64_t total_sid_infos;
	int64_t active_oid_infos;
	int64_t total_oid_infos;
	int64_t active_cid_infos;
	int64_t total_cid_infos;
	int64_t active_cr_infos;
	int64_t total_cr_infos;

	int64_t destination_throttles; /* due to max_packets_on_the_wire limit */
	int64_t destination_ignores;

	int64_t udp_receive_buffer_size;
	int64_t udp_send_buffer_size;
	int64_t udp_send_buffer_overflow;
	int64_t packets_on_the_wire;
	int64_t max_packets_on_the_wire;
	int64_t global_throttles;
};

extern struct timeval prog_start;
extern struct program_stats PS;

struct ber
{
	unsigned char *buf;
	unsigned char *b;
	int len;
	int max_len;
};

extern struct ber BER_NULL;
extern struct ber BER_TIMEOUT;
extern struct ber BER_MISSING;
extern struct ber BER_IGNORED;
extern struct ber BER_NON_INCREASING;

struct packet_info
{
	bool v3;
	/// @brief offset in packet to 4 bytes of sid (request-id/message-id);
	/// impl: v3: adjust for gdata and packet_sequence, v1/v2: adjust for pdu and packet_sequence
	unsigned sid_offset;
	/// @brief offset in packet to 12 bytes of msgAuthenticationParameters in SNMPv3 (HMAC-SHA-96);
	/// impl: adjust for sec_params_seq, sec_params_string, and packet_sequence
	unsigned authp_offset;
	/// @brief offset in packet to 8 bytes of msgPrivacyParameters in SNMPv3 (salt/iv);
	/// impl: adjust for sec_params_seq, sec_params_string, and packet_sequence
	unsigned privp_offset;
};

struct packet_builder
{
	struct ber e;
	unsigned char *packet_sequence;
	unsigned char *encrypted_pdu;
	unsigned char *decrypted_scoped_pdu;
	unsigned char *pdu;
	unsigned char *oid_sequence;
	unsigned char *max_repetitions;
	struct packet_info pi;
};

struct send_buf
{
	TAILQ_ENTRY(send_buf) send_list;
	unsigned char *buf;
	int size;
	int buf_size;
	int offset;
};

struct socket_info
{
	int fd;
	struct timeval created;
	void *udata;
	void (*read_handler)(struct socket_info *si);
	void (*write_handler)(struct socket_info *si);
	void (*eof_handler)(struct socket_info *si);
	int n_send_bufs;
	TAILQ_HEAD(send_buf_head, send_buf) send_bufs;
	struct program_stats PS;
};

struct client_connection
{
	msgpack_unpacker unpacker;
	msgpack_unpacked input;
};

#define DEFAULT_MAX_PACKETS_ON_THE_WIRE 3
#define DEFAULT_MAX_REQUEST_PACKET_SIZE 1400
#define DEFAULT_MAX_REPLY_PACKET_SIZE 1472
#define DEFAULT_ESTIMATED_VALUE_SIZE  9
#define DEFAULT_MAX_OIDS_PER_REQUEST  64
#define DEFAULT_TIMEOUT 2000
#define DEFAULT_RETRIES 3
#define DEFAULT_MIN_INTERVAL 10
#define DEFAULT_MAX_REPETITIONS 10
#define DEFAULT_IGNORE_THRESHOLD 0
#define DEFAULT_IGNORE_DURATION  300000

TAILQ_HEAD(oid_info_head, oid_info);
TAILQ_HEAD(sid_info_head, sid_info);
TAILQ_HEAD(client_requests_info_head, client_requests_info);
TAILQ_HEAD(destination_head, destination);

struct destination
{
	TAILQ_ENTRY(destination) timer_chain;
	struct in_addr ip;
	unsigned port;
	struct sockaddr_in dest_addr;

	int packets_on_the_wire;
	struct timeval can_query_at;
	int fd_of_last_query;
	JudyL client_requests_info;   /* JudyL of struct client_requests_info indexed by fd */
	JudyL sid_info;  /* JudyL of struct sid_info indexed by sid */
	int timeouts_in_a_row;
	struct timeval ignore_until;

	/* setopt-controlled parameters */
	int max_packets_on_the_wire;
	int max_request_packet_size;
	int max_reply_packet_size;
	int estimated_value_size;
	int max_oids_per_request;
	int min_interval;
	int max_repetitions;
	int ignore_threshold;
	int ignore_duration;

	/* destination-specific stats */
	int64_t octets_received;
	int64_t octets_sent;
};

#define V3O_ENGINE_ID_MAXLEN 64
#define V3O_USERNAME_MAXSIZE 64
#define V3O_AUTHPASS_MAXSIZE 64
#define V3O_PRIVPASS_MAXSIZE 64
#define V3O_AUTHKUL_MAXSIZE  32
#define V3O_PRIVKUL_MAXSIZE  32

#define V3O_AUTH_PROTO_MD5 1
#define V3O_AUTH_PROTO_SHA1 2

#define V3O_PRIV_PROTO_DES 1
#define V3O_PRIV_PROTO_AES128 2
#define V3O_PRIV_PROTO_AES192 21
#define V3O_PRIV_PROTO_AES256 22
#define V3O_PRIV_PROTO_AES192_CISCO 31
#define V3O_PRIV_PROTO_AES256_CISCO 32
#define V3O_PRIV_PROTO_AES V3O_PRIV_PROTO_AES128

#define V3F_REPORTABLE		0x04
#define V3F_ENCRYPTED		0x02
#define V3F_AUTHENTICATED	0x01

struct snmpv3info {
	// these can be set via setopt and (mostly) obtained via getopt
	unsigned  engine_id_len;
	u_int8_t  engine_id[V3O_ENGINE_ID_MAXLEN];
	char      username[V3O_USERNAME_MAXSIZE];
	int       auth_proto;
	char      authpass[V3O_AUTHPASS_MAXSIZE];
	unsigned  authkul_len;
	u_int8_t  authkul[V3O_AUTHKUL_MAXSIZE];
	int       priv_proto;
	char      privpass[V3O_PRIVPASS_MAXSIZE];
	unsigned  privkul_len;
	u_int8_t  privkul[V3O_AUTHKUL_MAXSIZE];
	// these cannot be set via setopt or obtained via getopt
	unsigned  x_privkul_len;
	u_int8_t  x_privkul[V3O_AUTHKUL_MAXSIZE]; // expanded kul if expansion is needed, or privkul copy if not
	unsigned  msg_max_size;
	// these are for packets we receive from the network
	u_int32_t engine_boots;
	u_int32_t engine_time;
	u_int8_t  msg_flags;
};

struct client_requests_info
{
	struct destination *dest;
	struct socket_info *si;
	int fd;
	JudyL cid_info; /* JudyL of struct cid_info ("cid" = client id) indexed by cid */
	struct oid_info_head oids_to_query;
	struct sid_info_head sid_infos;

	/* setopt-controlled parameters */
	unsigned version;
	char     community[256];
	int      timeout;
	int      retries;
	struct snmpv3info *v3;
};

struct cid_info
{
	unsigned cid;
	int fd;
	struct client_requests_info *cri;
	int n_oids;
	int n_oids_being_queried;
	int n_oids_done;
	struct oid_info_head oids_done;
};

struct timer
{
	struct timeval when;
	struct sid_info_head            timed_out_sids;
	struct destination_head         throttled_destinations;
};

struct sid_info
{
	TAILQ_ENTRY(sid_info) sid_list;
	TAILQ_ENTRY(sid_info) timer_chain;
	unsigned sid;
	struct client_requests_info *cri;
	struct timeval will_timeout_at;
	int retries_left;
	unsigned version;

	struct packet_builder pb;
	struct ber packet;
	struct packet_info pi;
	/* For a given SNMP request, either table_oid is not NULL,
	 * or oids_being_queried is non-empty.  This distinguishes
	 * between table walks and normal gets. */
	struct oid_info *table_oid; /* starting oid for GETTABLE */
	struct oid_info_head oids_being_queried;
};

struct oid_info
{
	TAILQ_ENTRY(oid_info) oid_list;
	unsigned sid;
	unsigned cid;
	int fd;
	/* If last_known_table_entry is not NULL, this structure
	 * represents the requested table.  If it is NULL,
	 * then this structure is just a normal OID being
	 * requested. */
	struct oid_info *last_known_table_entry;
	int max_repetitions;  /* only applicable when last_known_table_entry is not NULL */
	struct ber oid;
	struct ber value;
};

extern int opt_quiet;

/* ber.c */
extern struct ber ber_init(void *buf, int size);
extern struct ber ber_dup(struct ber *e);
extern struct ber ber_rewind(struct ber o);
extern void ber_dump(FILE *f, struct ber *e);
extern int ber_equal(struct ber *b1, struct ber *b2);
extern int ber_is_null(struct ber *ber);
extern struct ber ber_error_status(int error_status);

extern struct ber usmStatsNotInTimeWindows;
extern struct ber usmStatsWrongDigests;

extern int populate_well_known_oids(void);

extern int encode_type_len(unsigned char type, unsigned i, struct ber *e);
extern int encode_integer(unsigned i, struct ber *e, int force_size);
extern int encode_string(const char *s, struct ber *e);
extern int encode_bytes(const unsigned char *p, int n, struct ber *e);
extern int encode_string_oid(const char *oid, int oid_len, struct ber *e);
extern int encode_store_length(struct ber *e, unsigned char *s);

extern int decode_type_len(struct ber *e, unsigned char *type, unsigned *len);
extern int decode_integer(struct ber *e, int int_len, unsigned *value);
extern int decode_string(struct ber *e, unsigned char *s, unsigned s_size, unsigned *s_len); // adds nul byte, needs space for it
extern int decode_octets(struct ber *e, unsigned char *s, unsigned s_size, unsigned *s_len);  // does not add nul byte
extern int decode_ipv4_address(struct ber *e, int l, struct in_addr *ip);
extern int decode_counter64(struct ber *e, int int_len, unsigned long long *value);
extern int decode_timeticks(struct ber *e, int int_len, unsigned long long *value);
extern unsigned char *decode_string_oid(unsigned char *s, int l, char *buf, int buf_size);
extern int decode_composite(struct ber *e, unsigned char comp_type, int *composite_end_pos);
#define decode_sequence(e,seq_end_pos) decode_composite(e,AT_SEQUENCE,seq_end_pos)
#define inside_composite(e,s) ((e)->len < s)
#define inside_sequence(e,s) ((e)->len < s)

/* In decode_any() and decode_oid(),
 * the dst buffer will point inside the src buffer,
 * so if you are going to use it past the life of the src
 * buffer, do not forget to ber_dup(dst) afterwards.
 */
extern int decode_any(struct ber *src, struct ber *dst);
extern int decode_oid(struct ber *src, struct ber *dst);

extern int build_get_request_packet(int version, const char *community,
									const char *oid_list,
									unsigned request_id, struct ber *e);

extern int
start_snmp_packet(struct packet_builder* pb,
                  int version,
                  unsigned request_id,
                  const struct snmpv3info* v3,
                  const char* community);

extern int add_encoded_oid_to_snmp_packet(struct packet_builder *pb, struct ber *oid);
extern int
finalize_snmp_packet(struct packet_builder* pb,
                     struct ber* out_encoded_packet,
					 const struct snmpv3info* v3,
                     struct packet_info* out_pi,
                     unsigned char type,
                     int max_repetitions);
extern int oid_belongs_to_table(struct ber *oid, struct ber *table);
extern int oid_compare(struct ber *aa, struct ber *bb);
/* returns -9999 if there is a problem,
 * returns < 0 if a precedes b,
 * returns > 0 if a follows b,
 * return 0 if a is b
 */

/* other locations */
const char *thisprogname(void);
void croak(int exit_code, const char *fmt, ...);
void croakx(int exit_code, const char *fmt, ...);

/* event_loop.c */
struct socket_info *new_socket_info(int fd);
void delete_socket_info(struct socket_info *si);
void on_eof(struct socket_info *si, void (*eof_handler)(struct socket_info *si));
void on_read(struct socket_info *si, void (*read_handler)(struct socket_info *si));
void on_write(struct socket_info *si, void (*write_handler)(struct socket_info *si));
void event_loop(void);
void tcp_send(struct socket_info *si, void *buf, int size);

/* timers.c */
extern struct timer *new_timer(struct timeval *when);
extern struct timer *find_timer(struct timeval *when);
extern int cleanup_timer(struct timer *t);  /* 0 - not cleaned, 1 - cleaned */
extern struct timer *next_timer(void);
extern int ms_to_next_timer(void);
extern void trigger_timers(void);
extern void set_timeout(struct timeval *tv, int timeout);  /* timeout in ms */
extern int64_t ms_passed_since(struct timeval *tv);

/* client_listen.c */
extern void create_listening_socket(int port);

/* snmp.c */
extern void create_snmp_socket(void);
extern void snmp_send(struct destination *dest, struct ber *packet);

/* client_input.c */
extern void new_client_connection(int fd);

/* util.c */
extern char *object_strdup(msgpack_object *o);
extern char *object2string(msgpack_object *o, char s[], int bufsize);
extern size_t object_hexstring_to_buffer(msgpack_object *o, uint8_t *buf, size_t bufsize);
extern int object_string_eq(msgpack_object *o, char *s);
extern int object2ip(msgpack_object *o, struct in_addr *ip); /* 1 = success, 0 = failure */
extern unsigned next_sid(void);
extern void dump_buf(FILE *f, void *buf, int len);
extern char *oid2str(struct ber o);
extern char *timestring(void);

/* destination.c */
/* get_destination() cannot return NULL, it would rather die */
extern struct destination *get_destination(struct in_addr *ip, unsigned port);
extern struct destination *find_destination(struct in_addr *ip, unsigned port);
extern void maybe_query_destination(struct destination *dest);
extern void destination_start_timing(struct destination *dest);
extern void destination_stop_timing(struct destination *dest);
extern void destination_timer(struct destination *dest);
extern void dump_all_destinations(msgpack_packer *pk);
extern void unclog_all_destinations(void);

/* client_requests_info.c */
extern struct client_requests_info *get_client_requests_info(struct in_addr *ip, unsigned port, struct socket_info *si);
extern int free_client_request_info(struct client_requests_info *cri);
extern int free_all_client_request_info_for_fd(int fd);
extern void dump_client_request_info(msgpack_packer *pk, struct client_requests_info *cri);

/* cid_info.c */
extern struct cid_info *get_cid_info(struct client_requests_info *cri, unsigned cid);
extern int free_cid_info(struct cid_info *ci);
extern void cid_reply(struct cid_info *ci, int type);
extern void dump_cid_info(msgpack_packer *pk, struct cid_info *ci);

/* sid_info.c */
extern struct sid_info *new_sid_info(struct client_requests_info *cri);
extern struct sid_info *find_sid_info(struct destination *dest, unsigned sid);
extern void free_sid_info(struct sid_info *si);
extern void resend_query_with_new_sid(struct sid_info *si);
extern void build_snmp_query(struct client_requests_info *cri);
extern void sid_start_timing(struct sid_info *si);
extern void sid_stop_timing(struct sid_info *si);
extern int process_sid_info_response(struct sid_info *si, struct ber *e);
extern void oid_done(struct sid_info *si, struct oid_info *oi, struct ber *val, int op, int packet_error_status);
extern void all_oids_done(struct sid_info *si, struct ber *val);
extern void got_table_oid(struct sid_info *si, struct oid_info *table_oi, struct ber *oid, struct ber *val, int packet_error_status);
extern void sid_timer(struct sid_info *si);
extern void dump_sid_info(msgpack_packer *pk, struct sid_info *si);

/* oid_info.c */
extern int allocate_oid_info_list(struct oid_info_head *oi, msgpack_object *o, struct cid_info *ci);
extern struct oid_info *allocate_oid_info(msgpack_object *o, struct cid_info *ci);
extern int free_oid_info_list(struct oid_info_head *list);
extern int free_oid_info(struct oid_info *oi);  /* use only for oid_infos outside any lists */
extern void dump_oid_info(msgpack_packer *pk, struct oid_info *oi);

/* request_common.c */
extern int error_reply(struct socket_info *si, unsigned code, unsigned cid, char *error);
extern int msgpack_pack_string(msgpack_packer *pk, char *s);
extern int msgpack_pack_named_int(msgpack_packer *pk, char *name, int64_t val);
extern int msgpack_pack_named_string(msgpack_packer *pk, char *name, char *val);
extern int msgpack_pack_options(msgpack_packer *pk, struct client_requests_info *cri);
extern void msgpack_pack_oid(struct msgpack_packer *pk, struct ber oid);
extern void msgpack_pack_ber(struct msgpack_packer *pk, struct ber value);

/* request_setopt.c */
extern int handle_setopt_request(struct socket_info *si, unsigned cid, msgpack_object *o);

/* request_getopt.c */
extern int handle_getopt_request(struct socket_info *si, unsigned cid, msgpack_object *o);

/* request_info.c */
extern int handle_info_request(struct socket_info *si, unsigned cid, msgpack_object *o);
extern int handle_dest_info_request(struct socket_info *si, unsigned cid, msgpack_object *o);

/* request_get.c */
extern int handle_get_request(struct socket_info *si, unsigned cid, msgpack_object *o);

/* request_gettable.c */
extern int handle_gettable_request(struct socket_info *si, unsigned cid, msgpack_object *o);

/* v3_keys.c */
extern bool
password_to_key(int algorithm,
                void* pass,
             	unsigned pass_size,
                void* keybuf,
                unsigned keybufsize,
                unsigned* out_keylen,
                char** out_error);

extern bool
key_to_kul(int algorithm,
           void* key,
           unsigned key_size,
           void* engine_id,
           unsigned engine_id_size,
           void* out_kul,
           unsigned out_kul_size,
           unsigned* out_kul_len,
           char** out_error);

extern bool
password_to_kul(int alg,
                void* pass,
                unsigned pass_size,
                void* engine_id,
                unsigned engine_id_size,
                void* out_kul,
                unsigned out_kul_size,
                unsigned* out_kul_len,
                char** out_error);

extern bool
expand_kul(int authalg,
           int privalg,
           void* kul,
           unsigned kul_size,
           void* engine_id,
           unsigned engine_id_size,
           void* out_x_kul,
           unsigned out_x_kul_size,
           unsigned* out_x_kul_len,
           char** out_error);

/* v3_crypto.c */
extern int encrypt_in_place(unsigned char *buf, int buf_len, unsigned char *privp, const struct snmpv3info *v3);
extern int decrypt_in_place(unsigned char *buf, int buf_len, unsigned char *privp, const struct snmpv3info *v3);

extern int
hmac_message(const struct snmpv3info* v3,
             unsigned char* out,
             unsigned out_size,
             unsigned char* msg,
             unsigned msg_len,
             unsigned char* auth_param);

#endif