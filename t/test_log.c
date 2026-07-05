/* ABOUTME: Unit tests for the log_enc() encoder and log_format() line
 * ABOUTME: assembler in log.c: journald priority-prefix mode vs plain timestamped mode. */
#include "../sqe.h"
#include "tap.h"

static void
is_enc(const char *val, const char *expected)
{
	char buf[256];
	log_enc(buf, sizeof(buf), val);
	if (!ok(strcmp(buf, expected) == 0, "enc(%s)", val))
		tap_diag("got: %s want: %s", buf, expected);
}

static void
is_fmt(enum log_level lvl, int jmode, const char *stamp, const char *msg,
    const struct log_field *f, size_t nf, const char *expected)
{
	char buf[512];
	log_format(buf, sizeof(buf), lvl, jmode, stamp, msg, f, nf);
	if (!ok(strcmp(buf, expected) == 0, "fmt: %s", expected))
		tap_diag("got: %s", buf);
}

int
main(void)
{
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
	ok(strcmp(log_u(42u), "42") == 0, "U(42)");
	ok(strcmp(log_i(-7), "-7") == 0, "I(-7)");
	ok(strcmp(log_hex(0xa2u), "0xa2") == 0, "HEX(0xa2)");
	{
		unsigned char b[] = { 0x30, 0x82, 0x0f };
		ok(strcmp(log_hexbuf(b, sizeof(b)), "30820f") == 0, "HEXBUF");
	}
	{
		/* ring holds >=4 distinct live values in one expression */
		const char *a = log_u(1), *b = log_u(2), *c = log_u(3), *d = log_u(4);
		ok(strcmp(a, "1") == 0 && strcmp(b, "2") == 0 &&
		   strcmp(c, "3") == 0 && strcmp(d, "4") == 0, "ring keeps 4 live");
	}
	{
		struct log_field none[1];
		is_fmt(LL_INFO, 0, "TS", "hello", none, 0,
		    "time=TS level=info msg=hello\n");
		is_fmt(LL_WARN, 1, "IGN", "hello", none, 0,
		    "<4>msg=hello\n");
		is_fmt(LL_INFO, 0, "TS", "two words", none, 0,
		    "time=TS level=info msg=\"two words\"\n");
	}
	{
		struct log_field f[] = {
			{ "peer", "10.0.0.1:161" },
			{ "sid",  "42" },
			{ "trace", "decoding pdu" },
		};
		is_fmt(LL_WARN, 0, "TS", "bad packet", f, 3,
		    "time=TS level=warn msg=\"bad packet\" "
		    "peer=10.0.0.1:161 sid=42 trace=\"decoding pdu\"\n");
		is_fmt(LL_WARN, 1, "IGN", "bad packet", f, 3,
		    "<4>msg=\"bad packet\" peer=10.0.0.1:161 sid=42 "
		    "trace=\"decoding pdu\"\n");
	}
	{
		char longval[601];
		char buf[8300], expected[8300];
		struct log_field f[] = { { "field", longval } };

		memset(longval, 'a', sizeof(longval) - 1);
		longval[sizeof(longval) - 1] = '\0';
		snprintf(expected, sizeof(expected),
		    "time=TS level=info msg=hello field=%s\n", longval);
		log_format(buf, sizeof(buf), LL_INFO, 0, "TS", "hello", f, 1);
		if (!ok(strcmp(buf, expected) == 0, "long field value is not truncated"))
			tap_diag("got len %zu want len %zu", strlen(buf), strlen(expected));
	}
	ok(log_wants(LL_ERROR) == 1, "wants error at default level");
	return tap_done();
}
