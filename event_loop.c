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
			croak(1, "kqueue");
	}
	{
		struct kevent set_ke, get_ke;
		int nev;

		set_ke.ident  = si->fd;
		set_ke.filter = EVFILT_READ;
		set_ke.flags  = EV_ADD | EV_RECEIPT;

		nev = kevent(kq, &set_ke, 1, &get_ke, 1, NULL);
		fprintf(stderr, "nev: %d, flags: %d\n", nev, get_ke.flags);
	}
#endif
}

#ifdef WITH_KQUEUE
void
event_loop(void)
{
	getchar();
}
#endif
