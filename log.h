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

struct log_field { const char *k, *v; };
int log_format(char *out, size_t outsz, enum log_level lvl, int journal_mode,
    const char *stamp, const char *msg,
    const struct log_field *fields, size_t nfields);

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
