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
