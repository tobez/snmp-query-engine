/* ABOUTME: Unit tests for the log_line() formatter in log.c:
 * ABOUTME: journald priority-prefix mode vs plain timestamped mode. */
#include "../sqe.h"
#include "tap.h"

static void
check_line(enum log_level lvl, int jmode, const char *stamp,
    const char *msg, const char *expected)
{
	char buf[512];

	log_line(buf, sizeof(buf), lvl, jmode, stamp, msg);
	if (!ok(strcmp(buf, expected) == 0, "log_line(%d,%d,%s): %s",
	    (int)lvl, jmode, stamp ? stamp : "-", expected))
		tap_diag("got: %s", buf);
}

static void
is_enc(const char *val, const char *expected)
{
	char buf[256];
	log_enc(buf, sizeof(buf), val);
	if (!ok(strcmp(buf, expected) == 0, "enc(%s)", val))
		tap_diag("got: %s want: %s", buf, expected);
}

int
main(void)
{
	check_line(LL_ERROR, 1, "IGNORED", "boom", "<3>boom\n");
	check_line(LL_WARN,  1, "IGNORED", "eek",  "<4>eek\n");
	check_line(LL_INFO,  1, "IGNORED", "hi",   "<6>hi\n");
	check_line(LL_DEBUG, 1, "IGNORED", "dbg",  "<7>dbg\n");
	check_line(LL_ERROR, 0, "STAMP", "boom", "STAMP error: boom\n");
	check_line(LL_WARN,  0, "STAMP", "eek",  "STAMP warn: eek\n");
	check_line(LL_INFO,  0, "STAMP", "hi",   "STAMP info: hi\n");
	check_line(LL_DEBUG, 0, "STAMP", "dbg",  "STAMP debug: dbg\n");
	is_enc("info",          "info");
	is_enc("10.0.0.1:161",  "10.0.0.1:161");
	is_enc("1.3.6.1.2.1",   "1.3.6.1.2.1");
	is_enc("hello world",   "\"hello world\"");
	is_enc("a=b",           "\"a=b\"");
	is_enc("say \"hi\"",    "\"say \\\"hi\\\"\"");
	is_enc("back\\slash",   "\"back\\\\slash\"");
	is_enc("",              "\"\"");
	is_enc("l1\nl2",        "\"l1\\nl2\"");
	is_enc("t\tend",        "\"t\\tend\"");
	is_enc("r\rend",        "\"r\\rend\"");
	is_enc("\x01",          "\"\\x01\"");
	return tap_done();
}
