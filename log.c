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
log_line(char *out, size_t outsz, enum log_level lvl, int jmode,
    const char *stamp, const char *msg)
{
	static const char *name[] = { "error", "warn", "info", "debug" };
	static const int prio[] = { 3, 4, 6, 7 };

	if (jmode)
		return snprintf(out, outsz, "<%d>%s\n", prio[lvl], msg);
	return snprintf(out, outsz, "%s %s: %s\n", stamp, name[lvl], msg);
}

void
log_vemit(enum log_level lvl, const char *fmt, va_list ap)
{
	char msg[1024], line[1200];

	if (lvl > opt_log_level)
		return;
	vsnprintf(msg, sizeof(msg), fmt, ap);
	log_line(line, sizeof(line), lvl, journal_mode, timestring(), msg);
	fputs(line, stderr);
}

#define LOG_FUNC(fn, lvl) \
void \
fn(const char *fmt, ...) \
{ \
	va_list ap; \
	va_start(ap, fmt); \
	log_vemit(lvl, fmt, ap); \
	va_end(ap); \
}

LOG_FUNC(log_error, LL_ERROR)
LOG_FUNC(log_warn, LL_WARN)
LOG_FUNC(log_info, LL_INFO)
LOG_FUNC(log_debug, LL_DEBUG)
