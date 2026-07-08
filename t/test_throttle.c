/* ABOUTME: Unit tests for the log_throttle windowed-coalescing primitive:
 * ABOUTME: allow accounting and flush_due window/reset logic with an injected clock. */
#include "../sqe.h"
#include "tap.h"

static struct timeval
tv(long sec)
{
	struct timeval t;
	t.tv_sec = sec;
	t.tv_usec = 0;
	return t;
}

int
main(void)
{
	struct log_throttle t;
	struct timeval now;

	memset(&t, 0, sizeof(t));

	now = tv(1000);
	ok(log_throttle_allow(&t, &now) == 1, "first event in window is allowed");
	ok(log_throttle_allow(&t, &now) == 0, "second event is suppressed");
	ok(log_throttle_allow(&t, &now) == 0, "third event is suppressed");
	is_int(t.suppressed, 2, "two events suppressed");

	now = tv(1005);	/* 5s < 10s window */
	is_int(log_throttle_flush_due(&t, &now), 0, "flush before window close returns 0");
	is_int(t.suppressed, 2, "counter unchanged before window close");

	now = tv(1011);	/* 11s >= 10s window */
	is_int(log_throttle_flush_due(&t, &now), 2, "flush at window close returns suppressed count");
	is_int(t.window_start.tv_sec, 0, "counter reset to idle after flush");

	now = tv(1011);
	ok(log_throttle_allow(&t, &now) == 1, "next event re-opens the window");

	now = tv(1022);
	is_int(log_throttle_flush_due(&t, &now), 0, "empty window flush returns 0");
	is_int(t.window_start.tv_sec, 0, "empty window still resets to idle");

	is_int(log_throttle_flush_due(&t, &now), 0, "flush on idle counter returns 0");

	return tap_done();
}
