#include "sqe.h"

void *socks = NULL;
int kq = -1;

struct socket_info *
new_socket_info(int fd)
{
	struct socket_info *si, **slot;

	si = malloc(sizeof(*si));
	if (!si)
		croak(1, "new_socket_info: malloc(socket_info)");
	bzero(si, sizeof(*si));
	si->fd = fd;
	JLI(slot, socks, fd);
	if (slot == PJERR)
		croak(2, "new_socket_info: JLI failed");
	if (*slot)
		croak(3, "new_socket_info: assertion failed, fd %d is already there", fd);
	*slot = si;
	return si;
}

void
delete_socket_info(struct socket_info *si)
{
	/* XXX */
}

void
on_read(struct socket_info *si, void (*read_handler)(struct socket_info *si))
{
	si->read_handler = read_handler;
#ifdef WITH_KQUEUE
	if (kq < 0) {
		if ( (kq = kqueue()) < 0)
			croak(1, "on_read: kqueue");
	}
	{
		struct kevent set_ke, get_ke;
		int nev;

		set_ke.ident  = si->fd;
		set_ke.filter = EVFILT_READ;
		set_ke.flags  = EV_ADD | EV_RECEIPT;
		if (!read_handler)
			set_ke.flags |= EV_DISABLE;

		nev = kevent(kq, &set_ke, 1, &get_ke, 1, NULL);
		if (nev < 0)
			croak(1, "on_read: kevent");
		if (nev != 1)
			croakx(1, "on_read: unexpected nev %d", nev);
		if ((get_ke.flags & EV_ERROR) == 0)
			croakx(1, "on_read: unexpectedly EV_ERROR is not set");
		if (get_ke.data != 0) {
			errno = get_ke.data;
			croak(1, "on_read: kevent (error in data)");
		}
	}
#endif
}

void
on_write(struct socket_info *si, void (*write_handler)(struct socket_info *si))
{
	si->write_handler = write_handler;
#ifdef WITH_KQUEUE
	if (kq < 0) {
		if ( (kq = kqueue()) < 0)
			croak(1, "on_write: kqueue");
	}
	{
		struct kevent set_ke, get_ke;
		int nev;

		set_ke.ident  = si->fd;
		set_ke.filter = EVFILT_WRITE;
		set_ke.flags  = EV_ADD | EV_RECEIPT;
		if (!write_handler)
			set_ke.flags |= EV_DISABLE;

		nev = kevent(kq, &set_ke, 1, &get_ke, 1, NULL);
		if (nev < 0)
			croak(1, "on_write: kevent");
		if (nev != 1)
			croakx(1, "on_write: unexpected nev %d", nev);
		if ((get_ke.flags & EV_ERROR) == 0)
			croakx(1, "on_write: unexpectedly EV_ERROR is not set");
		if (get_ke.data != 0) {
			errno = get_ke.data;
			croak(1, "on_write: kevent (error in data)");
		}
	}
#endif
}

#ifdef WITH_KQUEUE
void
event_loop(void)
{
	struct kevent ke[10];
	int nev, i;
	while (1) {
		nev = kevent(kq, NULL, 0, ke, 10, NULL);
		if (nev < 0)
			croak(1, "event_loop: kevent");
		for (i = 0; i < nev; i++) {
			struct socket_info *si, **slot;

			if (ke[i].filter == EVFILT_READ) {
				JLG(slot, socks, ke[i].ident);
				if (slot && *slot) {
					si = *slot;
					if (si->read_handler) {
						si->read_handler(si);
					} else {
						fprintf(stderr, "event_loop: EVFILT_READ: ident %u - socket does not have a read handler\n", (unsigned)ke[i].ident);
					}
				} else {
					fprintf(stderr, "event_loop: EVFILT_READ: ident %u - no FD found in socks\n", (unsigned)ke[i].ident);
				}
			} else if (ke[i].filter == EVFILT_WRITE) {
				JLG(slot, socks, ke[i].ident);
				if (slot && *slot) {
					si = *slot;
					if (si->write_handler) {
						si->write_handler(si);
					} else {
						fprintf(stderr, "event_loop: EVFILT_WRITE: ident %u - socket does not have a write handler\n", (unsigned)ke[i].ident);
					}
				} else {
					fprintf(stderr, "event_loop: EVFILT_WRITE: ident %u - no FD found in socks\n", (unsigned)ke[i].ident);
				}
			} else {
				fprintf(stderr, "event_loop: unexpected filter value %d, ident %u\n", ke[i].filter, (unsigned)ke[i].ident);
			}
		}
	}
}
#endif
