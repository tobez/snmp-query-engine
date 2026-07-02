/* ABOUTME: Minimal TAP-emitting test helpers shared by the C test programs.
 * ABOUTME: Tests print ok/not ok lines; tap_done() prints the plan and returns exit status. */
#ifndef SQE_TAP_H
#define SQE_TAP_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static int tap_test_count = 0;
static int tap_fail_count = 0;

static void
tap_diag(const char *fmt, ...)
{
	va_list ap;

	printf("# ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

static int
ok(int cond, const char *fmt, ...)
{
	va_list ap;

	tap_test_count++;
	if (!cond)
		tap_fail_count++;
	printf("%sok %d - ", cond ? "" : "not ", tap_test_count);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	return cond;
}

static int
is_int(long long got, long long expected, const char *fmt, ...)
{
	va_list ap;
	int cond = got == expected;

	tap_test_count++;
	if (!cond)
		tap_fail_count++;
	printf("%sok %d - ", cond ? "" : "not ", tap_test_count);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	if (!cond)
		tap_diag("got %lld, expected %lld", got, expected);
	return cond;
}

static int
is_mem(const void *got, const void *expected, int len, const char *fmt, ...)
{
	va_list ap;
	int cond = memcmp(got, expected, len) == 0;
	int i;

	tap_test_count++;
	if (!cond)
		tap_fail_count++;
	printf("%sok %d - ", cond ? "" : "not ", tap_test_count);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	if (!cond) {
		printf("#      got:");
		for (i = 0; i < len; i++)
			printf(" %02x", ((const unsigned char *)got)[i]);
		printf("\n# expected:");
		for (i = 0; i < len; i++)
			printf(" %02x", ((const unsigned char *)expected)[i]);
		printf("\n");
	}
	return cond;
}

static int
tap_done(void)
{
	printf("1..%d\n", tap_test_count);
	return tap_fail_count != 0;
}

#endif
