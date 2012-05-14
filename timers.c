/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2012, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

struct timeval prog_start;
static JudyL timers = NULL;

struct timer *
new_timer(struct timeval *when)
{
	void **sec_slot;
	struct timer **usec_slot, *t;

	JLI(sec_slot, timers, when->tv_sec);
	if (sec_slot == PJERR)
		croak(2, "new_timer: JLI(timers) failed");
	if (!*sec_slot) {
		PS.active_timers_sec++;
		PS.total_timers_sec++;
	}
	JLI(usec_slot, *sec_slot, when->tv_usec);
	if (usec_slot == PJERR)
		croak(2, "new_timer: JLI(*sec_slot) failed");
	if (!*usec_slot) {
		PS.active_timers_usec++;
		PS.total_timers_usec++;
		t = malloc(sizeof(*t));
		if (!t)
			croak(2, "new_timer: malloc(timer)");
		bzero(t, sizeof(*t));
		t->when = *when;
		TAILQ_INIT(&t->timed_out_sids);
		TAILQ_INIT(&t->throttled_destinations);
		*usec_slot = t;
	}
	return *usec_slot;
}

struct timer *
find_timer(struct timeval *when)
{
	void **sec_slot;
	struct timer **usec_slot;

	JLG(sec_slot, timers, when->tv_sec);
	if (sec_slot == PJERR)
		croak(2, "find_timer: JLG(timers) failed");
	if (!sec_slot) return NULL;

	JLG(usec_slot, *sec_slot, when->tv_usec);
	if (usec_slot == PJERR)
		croak(2, "find_timer: JLG(*sec_slot) failed");
	if (!usec_slot) return NULL;
	return *usec_slot;
}

int
cleanup_timer(struct timer *t)
{
	Word_t rc;
	void **sec_slot;
	struct timeval tv;

	if (!t)	return 1;
	if (!TAILQ_EMPTY(&t->timed_out_sids))	return 0;
	if (!TAILQ_EMPTY(&t->throttled_destinations))	return 0;
	tv = t->when;
	free(t);

	JLG(sec_slot, timers, tv.tv_sec);
	if (sec_slot == PJERR)
		croak(2, "cleanup_timer: JLG(timers)#1 failed");
	if (!sec_slot) return 1;
	JLD(rc, *sec_slot, tv.tv_usec);
	PS.active_timers_usec--;

	JLG(sec_slot, timers, tv.tv_sec);
	if (sec_slot == PJERR)
		croak(2, "cleanup_timer: JLG(timers)#2 failed");
	if (!sec_slot) return 1;
	if (!*sec_slot) {
		JLD(rc, timers, tv.tv_sec);
		PS.active_timers_sec--;
	}
	return 1;
}

int
ms_to_next_timer(void)
{
	struct timer *t;
	struct timeval now;

	t = next_timer();
	if (!t)	return 5000;

	gettimeofday(&now, NULL);
	if (now.tv_sec > t->when.tv_sec)	return 0;
	if (now.tv_sec == t->when.tv_sec) {
		if (now.tv_usec > t->when.tv_usec)	return 0;
		return (t->when.tv_usec - now.tv_usec)/1000;
	}
	if (t->when.tv_sec - now.tv_sec > 5)	return 5000;
	return 1000*(t->when.tv_sec - now.tv_sec) + ((int)t->when.tv_usec - (int)now.tv_usec)/1000;
}

struct timer *
next_timer(void)
{
	Word_t sec, usec;
	void **sec_slot;
	struct timer **usec_slot;

again:
	sec = 0;
	JLF(sec_slot, timers, sec);
	if (!sec_slot)	return NULL;
	usec = 0;
	JLF(usec_slot, *sec_slot, usec);
	if (!usec_slot)	return NULL;
	if (cleanup_timer(*usec_slot))	goto again;
	return *usec_slot;
}

void
trigger_timers(void)
{
	struct timer *t;
	struct timeval now;

	gettimeofday(&now, NULL);

again:
	t = next_timer();
	if (!t) return;
	if (t->when.tv_sec > now.tv_sec)	return;
	if (t->when.tv_sec == now.tv_sec && t->when.tv_usec > now.tv_usec)	return;
	if (!TAILQ_EMPTY(&t->throttled_destinations)) {
		destination_timer(TAILQ_FIRST(&t->throttled_destinations));
		goto again;
	}
	if (!TAILQ_EMPTY(&t->timed_out_sids)) {
		sid_timer(TAILQ_FIRST(&t->timed_out_sids));
		goto again;
	}
	cleanup_timer(t);
	goto again;
}

void
set_timeout(struct timeval *tv, int timeout)
{
	struct timeval to;
	gettimeofday(tv, NULL);
	to.tv_sec = timeout / 1000;
	to.tv_usec = 1000 * (timeout % 1000);
	to.tv_usec += tv->tv_usec;
	to.tv_sec  += tv->tv_sec;
	to.tv_sec  += to.tv_usec / 1000000;
	to.tv_usec %= 1000000;
	*tv = to;
}

int64_t
ms_passed_since(struct timeval *tv)
{
	struct timeval now;

	if (!tv->tv_sec)	return INT_MAX;
	gettimeofday(&now, NULL);
	return (now.tv_sec - tv->tv_sec) * 1000 + (now.tv_usec - tv->tv_usec) / 1000;
}

