/* ABOUTME: Leveled logging API: severity enum, pure line formatter, and
 * ABOUTME: printf-style emitters used by every diagnostic in the daemon. */
#ifndef SQE_LOG_H
#define SQE_LOG_H

#include <stdarg.h>
#include <stddef.h>

enum log_level { LL_ERROR, LL_WARN, LL_INFO, LL_DEBUG };

extern enum log_level opt_log_level;

void log_setup(void);
size_t log_enc(char *out, size_t outsz, const char *val);
int log_line(char *out, size_t outsz, enum log_level lvl, int journal_mode,
    const char *stamp, const char *msg);
void log_vemit(enum log_level lvl, const char *fmt, va_list ap);
void log_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_debug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif
