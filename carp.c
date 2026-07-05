/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012-2013, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

static void v(int use_errno, int exit_code, const char *fmt, va_list ap) __attribute__((noreturn));

void
croak(int exit_code, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	v(errno, exit_code, fmt, ap);
	va_end(ap);
}

void
croakx(int exit_code, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	v(-1, exit_code, fmt, ap);
	va_end(ap);
}

void
v(int use_errno, int exit_code, const char *fmt, va_list ap)
{
	char msg[1024];
	int len = 0;

	if (fmt != NULL)
		len = vsnprintf(msg, sizeof(msg), fmt, ap);
	if (len < 0)
		len = 0;
	if (use_errno >= 0 && (size_t)len < sizeof(msg))
		snprintf(msg + len, sizeof(msg) - len, "%s%s",
		    fmt ? ": " : "", strerror(use_errno));
	log_error(msg, NULL);
	exit(exit_code);
}

#if defined(__linux__)
static char proggy[MAXPATHLEN];
#endif

const char *thisprogname(void)
{
#if defined(__FreeBSD__)
	return getprogname();
#elif defined(__APPLE__)
	return getprogname();
#elif defined(__sun__)
	return getexecname();
#elif defined(__linux__)
	if (readlink("/proc/self/exe", proggy, MAXPATHLEN) != -1)
		return proggy;
	return "";
#else
#error "unsupported OS"
#endif
}
