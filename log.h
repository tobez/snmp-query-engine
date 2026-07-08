/* ABOUTME: Leveled logging API: severity enum, pure line formatter, and
 * ABOUTME: logfmt key-value emitters used by every diagnostic in the daemon. */
#ifndef SQE_LOG_H
#define SQE_LOG_H

#include <stdarg.h>
#include <stddef.h>
#include <sys/time.h>

enum log_level { LL_ERROR, LL_WARN, LL_INFO, LL_DEBUG };

extern enum log_level opt_log_level;

void log_setup(void);
size_t log_enc(char *out, size_t outsz, const char *val);
int log_wants(enum log_level lvl);

#define LOG_THROTTLE_WINDOW_SEC 10

struct log_throttle {
	unsigned       suppressed;     /* events coalesced since the window opened */
	struct timeval window_start;   /* tv_sec == 0 -> idle, no open window */
};

int log_throttle_allow(struct log_throttle *t, const struct timeval *now);
unsigned log_throttle_flush_due(struct log_throttle *t, const struct timeval *now);

enum log_throttle_cat {
	/* per-destination categories (index into dest->throttle) */
	LTC_LATE_REPLY = 0,
	LTC_NO_V3_INFO,
	LTC_ENGINE_ID_MISMATCH,
	LTC_USERNAME_MISMATCH,
	LTC_AUTH_FAILED,
	LTC_CANNOT_DECRYPT,
	LTC_AUTHCTX_ENGINE_MISMATCH,
	LTC_UNSUPPORTED_PDU,
	LTC_MSGID_MISMATCH,
	LTC_ERROR_STATUS,
	LTC_ERROR_INDEX,
	LTC_REPORT_BAD_DIGEST,
	LTC_REPORT,
	LTC_BAD_PACKET,
	LTC_OIDS_UNACCOUNTED,
	LTC_PERDEST_COUNT,	/* == number of per-destination categories */
	/* standalone categories (index into log.c static array as cat - LTC_PERDEST_COUNT) */
	LTC_UNKNOWN_DESTINATION = LTC_PERDEST_COUNT,
	LTC_SEND_BUFFER_OVERFLOW,
	LTC_INCOMING_CONNECTION,
	LTC_CLIENT_DISCONNECT,
	LTC_ACCEPT_FAILURE,
	LTC_COUNT
};

const char *log_throttle_cat_message(int cat);
int log_throttle_allow_standalone(enum log_throttle_cat cat);
void log_throttle_flush_standalone(const struct timeval *now);

struct log_field { const char *k, *v; };
int log_format(char *out, size_t outsz, enum log_level lvl, int journal_mode,
    const char *stamp, const char *msg,
    const struct log_field *fields, size_t nfields);
void log_throttle_rollup(enum log_throttle_cat cat, unsigned suppressed,
    const struct log_field *ctx, size_t nctx);

void log_error(const char *msg, ...) __attribute__((sentinel));
void log_warn (const char *msg, ...) __attribute__((sentinel));
void log_info (const char *msg, ...) __attribute__((sentinel));
void log_debug(const char *msg, ...) __attribute__((sentinel));
const char *log_u(unsigned v);
const char *log_i(int v);
const char *log_hex(unsigned v);
const char *log_hexbuf(const void *buf, size_t len);
#define U(x)        log_u(x)
#define I(x)        log_i(x)
#define HEX(x)      log_hex(x)
#define HEXBUF(b,l) log_hexbuf((b), (l))

#endif
