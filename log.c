/* ABOUTME: Leveled logging to stderr with journald-aware formatting:
 * ABOUTME: sd-daemon <N> priority prefixes under journald, timestamps otherwise. */
#include "sqe.h"

static int journal_mode = 0;

void
log_setup(void)
{
	const char *js = getenv("JOURNAL_STREAM");
	struct stat st;
	char buf[64];

	journal_mode = 0;
	if (js && fstat(STDERR_FILENO, &st) == 0) {
		snprintf(buf, sizeof(buf), "%llu:%llu",
		    (unsigned long long)st.st_dev, (unsigned long long)st.st_ino);
		if (strcmp(buf, js) == 0)
			journal_mode = 1;
	}
}

static int
needs_quote(const char *s)
{
	if (!*s)
		return 1;
	for (const unsigned char *p = (const unsigned char *)s; *p; p++)
		if (*p == ' ' || *p == '=' || *p == '"' || *p == '\\' || *p < 0x20)
			return 1;
	return 0;
}

size_t
log_enc(char *out, size_t outsz, const char *val)
{
	size_t n = 0;
	if (outsz == 0)
		return 0;
	if (!needs_quote(val)) {
		while (val[n] && n + 1 < outsz) {
			out[n] = val[n];
			n++;
		}
		out[n] = '\0';
		return n;
	}
	/* quoted form */
#define PUT(c) do { if (n + 1 < outsz) out[n++] = (c); } while (0)
	PUT('"');
	for (const unsigned char *p = (const unsigned char *)val; *p; p++) {
		unsigned char c = *p;
		if (c == '"' || c == '\\') { PUT('\\'); PUT(c); }
		else if (c == '\n') { PUT('\\'); PUT('n'); }
		else if (c == '\t') { PUT('\\'); PUT('t'); }
		else if (c == '\r') { PUT('\\'); PUT('r'); }
		else if (c < 0x20) {
			static const char hexd[] = "0123456789abcdef";
			PUT('\\'); PUT('x'); PUT(hexd[c >> 4]); PUT(hexd[c & 0xf]);
		} else PUT(c);
	}
	PUT('"');
#undef PUT
	out[n < outsz ? n : outsz - 1] = '\0';
	return n;
}

int
log_wants(enum log_level lvl)
{
	return lvl <= opt_log_level;
}

/* Largest legitimate field value is a HEXBUF() dump: HEXBUF_MAX_IN input
 * bytes hex-encoded to twice that many chars, plus a NUL. */
#define HEXBUF_MAX_IN 4096

int
log_format(char *out, size_t outsz, enum log_level lvl, int journal_mode,
    const char *stamp, const char *msg,
    const struct log_field *fields, size_t nfields)
{
	static const char *name[] = { "error", "warn", "info", "debug" };
	static const int prio[] = { 3, 4, 6, 7 };
	static char enc[2 * HEXBUF_MAX_IN + 1];
	size_t p = 0, i;

#define APPEND(...) do { \
	int _r = snprintf(out + (p < outsz ? p : outsz), p < outsz ? outsz - p : 0, __VA_ARGS__); \
	if (_r > 0) p += (size_t)_r; \
} while (0)

	if (journal_mode) {
		APPEND("<%d>", prio[lvl]);
	} else {
		APPEND("time=%s level=%s ", stamp, name[lvl]);
	}
	log_enc(enc, sizeof(enc), msg);
	APPEND("msg=%s", enc);
	for (i = 0; i < nfields; i++) {
		log_enc(enc, sizeof(enc), fields[i].v);
		APPEND(" %s=%s", fields[i].k, enc);
	}
	APPEND("\n");
#undef APPEND
	if (p >= outsz && outsz >= 2)
		out[outsz - 2] = '\n';
	return (int)p;
}

#define LOG_MAXFIELDS 16
#define LOG_LINESZ 8192

static void
log_vemit(enum log_level lvl, const char *msg, va_list ap)
{
	struct log_field f[LOG_MAXFIELDS];
	size_t n = 0;
	const char *k;
	char line[LOG_LINESZ];

	if (!log_wants(lvl))
		return;
	while ((k = va_arg(ap, const char *)) != NULL) {
		const char *v = va_arg(ap, const char *);
		if (n < LOG_MAXFIELDS) {
			f[n].k = k;
			f[n].v = v;
			n++;
		}
	}
	log_format(line, sizeof(line), lvl, journal_mode, timestring(), msg, f, n);
	fputs(line, stderr);
}

#define LOG_FUNC(fn, lvl) \
void \
fn(const char *msg, ...) \
{ \
	va_list ap; \
	va_start(ap, msg); \
	log_vemit(lvl, msg, ap); \
	va_end(ap); \
}

LOG_FUNC(log_error, LL_ERROR)
LOG_FUNC(log_warn, LL_WARN)
LOG_FUNC(log_info, LL_INFO)
LOG_FUNC(log_debug, LL_DEBUG)

#define RING_SLOTS 8
#define RING_SLOTSZ 32
static char ring[RING_SLOTS][RING_SLOTSZ];
static int ring_idx;

static char *
ring_next(void)
{
	char *s = ring[ring_idx];
	ring_idx = (ring_idx + 1) % RING_SLOTS;
	return s;
}

const char *
log_u(unsigned v)
{
	char *s = ring_next();
	snprintf(s, RING_SLOTSZ, "%u", v);
	return s;
}

const char *
log_i(int v)
{
	char *s = ring_next();
	snprintf(s, RING_SLOTSZ, "%d", v);
	return s;
}

const char *
log_hex(unsigned v)
{
	char *s = ring_next();
	snprintf(s, RING_SLOTSZ, "0x%x", v);
	return s;
}

static char hexbuf_buf[2 * HEXBUF_MAX_IN + 1];

const char *
log_hexbuf(const void *buf, size_t len)
{
	static const char hexd[] = "0123456789abcdef";
	const unsigned char *b = buf;
	size_t i, n = len > HEXBUF_MAX_IN ? HEXBUF_MAX_IN : len;
	for (i = 0; i < n; i++) {
		hexbuf_buf[2 * i]     = hexd[b[i] >> 4];
		hexbuf_buf[2 * i + 1] = hexd[b[i] & 0xf];
	}
	hexbuf_buf[2 * n] = '\0';
	return hexbuf_buf;
}

int
log_throttle_allow(struct log_throttle *t, const struct timeval *now)
{
	if (t->window_start.tv_sec == 0) {
		t->window_start = *now;
		t->suppressed = 0;
		return 1;
	}
	t->suppressed++;
	return 0;
}

unsigned
log_throttle_flush_due(struct log_throttle *t, const struct timeval *now)
{
	unsigned n;

	if (t->window_start.tv_sec == 0)
		return 0;   /* idle */
	if (now->tv_sec - t->window_start.tv_sec < LOG_THROTTLE_WINDOW_SEC)
		return 0;   /* window still open */
	n = t->suppressed;
	t->window_start.tv_sec = 0;
	t->suppressed = 0;
	return n;
}

static const struct {
	const char *msg;
	enum log_level lvl;
} log_throttle_cat_tab[LTC_COUNT] = {
	[LTC_LATE_REPLY]              = { "late reply, ignoring packet", LL_INFO },
	[LTC_NO_V3_INFO]              = { "no v3 info for reply, ignoring packet", LL_WARN },
	[LTC_ENGINE_ID_MISMATCH]      = { "engine-id mismatch, ignoring packet", LL_WARN },
	[LTC_USERNAME_MISMATCH]       = { "username mismatch, ignoring packet", LL_WARN },
	[LTC_AUTH_FAILED]             = { "authentication failed", LL_WARN },
	[LTC_CANNOT_DECRYPT]          = { "cannot decrypt, ignoring packet", LL_WARN },
	[LTC_AUTHCTX_ENGINE_MISMATCH] = { "authoritative/context engine-id mismatch, ignoring packet", LL_WARN },
	[LTC_UNSUPPORTED_PDU]         = { "unsupported PDU type, ignoring packet", LL_WARN },
	[LTC_MSGID_MISMATCH]          = { "message-id does not match request-id", LL_WARN },
	[LTC_ERROR_STATUS]            = { "non-zero error-status", LL_WARN },
	[LTC_ERROR_INDEX]             = { "non-zero error-index", LL_WARN },
	[LTC_REPORT_BAD_DIGEST]       = { "report: bad digest, ignoring packet", LL_WARN },
	[LTC_REPORT]                  = { "report", LL_WARN },
	[LTC_BAD_PACKET]              = { "bad SNMP packet, ignoring", LL_WARN },
	[LTC_OIDS_UNACCOUNTED]        = { "not all oids accounted for", LL_WARN },
	[LTC_UNKNOWN_DESTINATION]     = { "destination not known, ignoring packet", LL_WARN },
	[LTC_SEND_BUFFER_OVERFLOW]    = { "udp send buffer overflow, dropping datagram", LL_WARN },
	[LTC_INCOMING_CONNECTION]     = { "incoming connection", LL_INFO },
	[LTC_CLIENT_DISCONNECT]       = { "client disconnect", LL_INFO },
	[LTC_ACCEPT_FAILURE]          = { "cannot accept client connection", LL_WARN },
};

const char *
log_throttle_cat_message(int cat)
{
	if (cat < 0 || cat >= LTC_COUNT)
		return NULL;
	return log_throttle_cat_tab[cat].msg;
}

void
log_throttle_rollup(enum log_throttle_cat cat, unsigned suppressed,
    const struct log_field *ctx, size_t nctx)
{
	struct log_field f[LOG_MAXFIELDS];
	size_t n = 0, i;
	enum log_level lvl = log_throttle_cat_tab[cat].lvl;
	char line[LOG_LINESZ];

	if (!log_wants(lvl))
		return;
	for (i = 0; i < nctx && n < LOG_MAXFIELDS - 2; i++)
		f[n++] = ctx[i];
	f[n].k = "repeated";   f[n].v = log_u(suppressed);                n++;
	f[n].k = "interval_s"; f[n].v = log_u(LOG_THROTTLE_WINDOW_SEC);   n++;
	log_format(line, sizeof(line), lvl, journal_mode, timestring(),
	    log_throttle_cat_tab[cat].msg, f, n);
	fputs(line, stderr);
}

static struct log_throttle standalone_throttle[LTC_COUNT - LTC_PERDEST_COUNT];

int
log_throttle_allow_standalone(enum log_throttle_cat cat)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	return log_throttle_allow(&standalone_throttle[cat - LTC_PERDEST_COUNT], &now);
}

void
log_throttle_flush_standalone(const struct timeval *now)
{
	enum log_throttle_cat cat;

	for (cat = LTC_PERDEST_COUNT; cat < LTC_COUNT; cat++) {
		unsigned n = log_throttle_flush_due(
		    &standalone_throttle[cat - LTC_PERDEST_COUNT], now);
		if (n)
			log_throttle_rollup(cat, n, NULL, 0);
	}
}
