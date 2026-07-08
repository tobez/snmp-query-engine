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

	/* --- category table is fully populated --- */
	{
		int cat, all_ok = 1;
		for (cat = 0; cat < LTC_COUNT; cat++)
			if (log_throttle_cat_message(cat) == NULL)
				all_ok = 0;
		ok(all_ok, "every category has a message");
	}

	/* --- standalone adapter: first allowed, repeats suppressed in-window --- */
	{
		int a = log_throttle_allow_standalone(LTC_UNKNOWN_DESTINATION);
		int b = log_throttle_allow_standalone(LTC_UNKNOWN_DESTINATION);
		int c = log_throttle_allow_standalone(LTC_UNKNOWN_DESTINATION);
		ok(a == 1 && b == 0 && c == 0, "standalone: first allowed, repeats suppressed");
	}

	/* --- per-destination adapter: lazy alloc + in-window suppression --- */
	{
		struct destination d;
		unsigned n;
		struct timeval future;

		memset(&d, 0, sizeof(d));
		ok(d.throttle == NULL, "destination starts with no throttle array");
		ok(destination_log_allow(&d, LTC_BAD_PACKET) == 1, "per-dest: first allowed");
		ok(d.throttle != NULL, "throttle array lazily allocated on first use");
		ok(destination_log_allow(&d, LTC_BAD_PACKET) == 0, "per-dest: repeat suppressed");
		ok(destination_log_allow(&d, LTC_BAD_PACKET) == 0, "per-dest: repeat suppressed");
		is_int(d.throttle[LTC_BAD_PACKET].suppressed, 2, "per-dest: two suppressed");

		future = d.throttle[LTC_BAD_PACKET].window_start;
		future.tv_sec += LOG_THROTTLE_WINDOW_SEC + 1;
		n = log_throttle_flush_due(&d.throttle[LTC_BAD_PACKET], &future);
		is_int(n, 2, "per-dest: flush after window returns suppressed count");
		free(d.throttle);
	}

	return tap_done();
}
