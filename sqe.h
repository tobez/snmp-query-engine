#ifndef _COMMON_H
#define _COMMON_H

#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>
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

#define RI_TYPE          0
#define RI_CID           1
#define RI_GET_IP        2
#define RI_GET_PORT      3
#define RI_GET_SNMP_VER  4
#define RI_GET_COMMUNITY 5
#define RI_GET_OIDS      6
#define RI_GET_PARAMS    7

#define RT_GET 0

#define AT_INTEGER  2
#define AT_STRING   4
#define AT_NULL		5
#define AT_OID      6
#define AT_SEQUENCE 0x30

#define MAX_OID 268435455  /* 2^28-1 to fit into 4 bytes */

#define PDU_GET_REQUEST 0xa0

typedef void* JudyL;
typedef void* JudyHS;

struct encode
{
	unsigned char *buf;
	unsigned char *b;
	int len;
	int max_len;
};

struct packet_builder
{
	unsigned char *packet_sequence;
	unsigned char *pdu;
	unsigned char *oid_sequence;
	struct encode e;
};

struct socket_info;

struct socket_info
{
	int fd;
	void *udata;
	void (*read_handler)(struct socket_info *si);
	void (*write_handler)(struct socket_info *si);
};

struct client_connection
{
	msgpack_unpacker unpacker;
	msgpack_unpacked input;
};

#define DEFAULT_MAX_PACKETS_ON_THE_WIRE 3
#define DEFAULT_MAX_REQUEST_PACKET_SIZE 1400
#define DEFAULT_TIMEOUT 2000
#define DEFAULT_RETRIES 3

struct destination
{
	struct in_addr ip;
	unsigned port;
	unsigned version;
	char community[256];
	struct sockaddr_in dest_addr;
	int max_packets_on_the_wire;
	int max_request_packet_size;
	int timeout;
	int retries;

	int fd_of_last_query;
	JudyL client_requests_info;   /* JudyL of struct client_requests_info indexed by fd */
	JudyL sid_info;  /* JudyL of struct sid_info indexed by sid */
};

TAILQ_HEAD(oid_info_head, oid_info);
TAILQ_HEAD(sid_info_head, sid_info);

struct client_requests_info
{
	struct destination *dest;
	int fd;
	JudyL cid_info; /* JudyL of struct cid_info ("cid" = client id) indexed by cid */
	struct oid_info_head oids_to_query;
	struct sid_info_head sid_infos;
};

struct cid_info
{
	unsigned cid;
	int fd;
	int n_oids;
	int n_oids_being_queried;
	int n_oids_done;
	struct oid_info_head oids_done;
};

struct sid_info
{
	TAILQ_ENTRY(sid_info) sid_list;
	TAILQ_ENTRY(sid_info) same_timeout;
	unsigned sid;
	struct client_requests_info *cri;
	struct timeval will_timeout_at;

	struct packet_builder pb;
	struct encode packet;
	struct oid_info_head oids_being_queried;
};

struct oid_info
{
	TAILQ_ENTRY(oid_info) oid_list;
	unsigned sid;
	unsigned cid;
	int fd;
	// XXX some kind of distinguisher between table walk and get
	struct encode oid;
	struct encode value;
};

extern int opt_quiet;

/* ber.c */
extern struct encode encode_init(void *buf, int size);
extern struct encode encode_dup(struct encode *e);
extern int encode_type_len(unsigned char type, unsigned i, struct encode *e);
extern int encode_integer(unsigned i, struct encode *e, int force_size);
extern int encode_string(const char *s, struct encode *e);
extern int encode_string_oid(const char *oid, int oid_len, struct encode *e);
extern int encode_store_length(struct encode *e, unsigned char *s);
extern void encode_dump(FILE *f, struct encode *e);
extern unsigned char *decode_string_oid(unsigned char *s, int l, char *buf, int buf_size);

extern int build_get_request_packet(int version, const char *community,
									const char *oid_list,
									unsigned request_id, struct encode *e);
extern int start_snmp_get_packet(struct packet_builder *pb, int version, const char *community,
								 unsigned request_id);
extern int add_encoded_oid_to_snmp_packet(struct packet_builder *pb, struct encode *oid);
extern int finalize_snmp_packet(struct packet_builder *pb, struct encode *encoded_packet);

/* other locations */
const char *thisprogname(void);
void croak(int exit_code, const char *fmt, ...);
void croakx(int exit_code, const char *fmt, ...);
struct socket_info *new_socket_info(int fd);
void delete_socket_info(struct socket_info *si);
void on_read(struct socket_info *si, void (*read_handler)(struct socket_info *si));
void on_write(struct socket_info *si, void (*write_handler)(struct socket_info *si));
void event_loop(void);

/* client_listen.c */
extern void create_listening_socket(int port);

/* snmp.c */
extern void create_snmp_socket(void);
extern void snmp_send(struct destination *dest, struct encode *packet);

/* client_input.c */
extern void new_client_connection(int fd);

/* util.c */
extern char *object_strdup(msgpack_object *o);
extern char *object2string(msgpack_object *o, char s[], int bufsize);
extern int object2ip(msgpack_object *o, struct in_addr *ip); /* 1 = success, 0 = failure */
extern unsigned next_sid(void);
extern void dump_buf(FILE *f, void *buf, int len);

/* destination.c */
/* get_destination() cannot return NULL, it would rather die */
extern struct destination *get_destination(struct in_addr *ip, unsigned port);
extern void maybe_query_destination(struct destination *dest);

/* client_requests_info.c */
extern struct client_requests_info *get_client_requests_info(struct in_addr *ip, unsigned port, int fd);
extern int free_client_request_info(struct client_requests_info *cri);
extern int free_all_client_request_info_for_fd(int fd);

/* cid_info.c */
extern struct cid_info *get_cid_info(struct client_requests_info *cri, unsigned cid);
extern int free_cid_info(struct cid_info *ci, struct destination *dest);

/* sid_info.c */
extern struct sid_info *new_sid_info(struct client_requests_info *cri);
extern void free_sid_info(struct sid_info *si);
extern void build_snmp_query(struct client_requests_info *cri);
extern void sid_start_timing(struct sid_info *si);
extern void sid_stop_timing(struct sid_info *si);
extern int sid_next_timeout(void);
extern void check_timed_out_requests(void);

/* oid_info.c */
extern int allocate_oid_info_list(struct oid_info_head *oi, msgpack_object *o, struct cid_info *ci);
extern int free_oid_info_list(struct oid_info_head *list);

#endif
