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
	int _r = snprintf(out + p, p < outsz ? outsz - p : 0, __VA_ARGS__); \
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
