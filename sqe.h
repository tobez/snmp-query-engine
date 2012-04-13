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
#define RI_ID            1
#define RI_GET_IP        2
#define RI_GET_PORT      3
#define RI_GET_SNMP_VER  4
#define RI_GET_COMMUNITY 5
#define RI_GET_OIDS      6
#define RI_GET_PARAMS    7

#define RT_GET 0

typedef void* JudyL;
typedef void* JudyHS;

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

struct destination
{
	unsigned version;
	char community[256];
	JudyL client_requests_info;   /* JudyL of struct client_requests_info indexed by fd */
	JudyL sid_info;  /* JudyL of (JudyHS of struct oid_info indexed by oid) indexed by sid */
};

TAILQ_HEAD(oid_info_head, oid_info);

struct client_requests_info
{
	struct destination *dest;
	JudyL cid_info; /* JudyL of struct cid_info ("cid" = client id) indexed by cid */
	struct oid_info_head oids_to_query;
};

struct cid_info
{
	unsigned cid;
	unsigned n_oids;
	unsigned n_oids_being_queried;
	unsigned n_oids_done;
	struct oid_info_head oids_being_queried;
	struct oid_info_head oids_done;
};

struct oid_info
{
	TAILQ_ENTRY(oid_info) oid_list;
	unsigned sid;
	unsigned cid;
	int fd;
	// some kind of distinguisher between table walk and get
	// struct encode oid
	// struct encode value
};

extern int opt_quiet;

const char *thisprogname(void);
void croak(int exit_code, const char *fmt, ...);
void croakx(int exit_code, const char *fmt, ...);
struct socket_info *new_socket_info(int fd);
void delete_socket_info(struct socket_info *si);
void on_read(struct socket_info *si, void (*read_handler)(struct socket_info *si));
void on_write(struct socket_info *si, void (*write_handler)(struct socket_info *si));
void event_loop(void);

/* client_listen.c */
void create_listening_socket(int port);

/* client_input.c */
void new_client_connection(int fd);

/* util.c */
char *object_strdup(msgpack_object *o);
char *object2string(msgpack_object *o, char s[], int bufsize);
int object2ip(msgpack_object *o, struct in_addr *ip); /* 1 = success, 0 = failure */

/* destination.c */
/* get_destination() cannot return NULL, it would rather die */
struct destination *get_destination(struct in_addr *ip, unsigned port);

/* client_requests_info.c */
struct client_requests_info *get_client_requests_info(struct in_addr *ip, unsigned port, int fd);

#endif
