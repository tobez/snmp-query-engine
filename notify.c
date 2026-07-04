/* ABOUTME: systemd sd_notify protocol, hand-rolled: readiness, stopping and
 * ABOUTME: watchdog datagrams to $NOTIFY_SOCKET; no-op outside systemd. */
#include "sqe.h"

static int notify_fd = -1;
static struct sockaddr_un notify_addr;
static socklen_t notify_addrlen = 0;
static int watchdog_period_ms = 0;
static struct timeval last_watchdog;

void
notify_init(void)
{
	const char *path = getenv("NOTIFY_SOCKET");
	const char *usec = getenv("WATCHDOG_USEC");
	const char *wpid = getenv("WATCHDOG_PID");
	size_t len;

	if (!path || (path[0] != '/' && path[0] != '@'))
		return;
	len = strlen(path);
	if (len >= sizeof(notify_addr.sun_path))
		return;
	memset(&notify_addr, 0, sizeof(notify_addr));
	notify_addr.sun_family = AF_UNIX;
	memcpy(notify_addr.sun_path, path, len);
	if (path[0] == '@')
		notify_addr.sun_path[0] = '\0';
	notify_addrlen = offsetof(struct sockaddr_un, sun_path) + len;
	if ( (notify_fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		log_debug("notify_init: socket: %s", strerror(errno));
		return;
	}
	if (usec && (!wpid || atoi(wpid) == (int)getpid())) {
		long period = atol(usec) / 3 / 1000;
		if (period > 0)
			watchdog_period_ms = (int)period;
	}
	gettimeofday(&last_watchdog, NULL);
}

void
notify(const char *state)
{
	if (notify_fd < 0)
		return;
	if (sendto(notify_fd, state, strlen(state), 0,
	    (struct sockaddr *)&notify_addr, notify_addrlen) < 0)
		log_debug("notify: sendto: %s", strerror(errno));
}

void
notify_watchdog_tick(void)
{
	if (notify_fd < 0 || !watchdog_period_ms)
		return;
	if (ms_passed_since(&last_watchdog) >= watchdog_period_ms) {
		notify("WATCHDOG=1");
		gettimeofday(&last_watchdog, NULL);
	}
}

int
notify_watchdog_interval_ms(void)
{
	return watchdog_period_ms;
}
