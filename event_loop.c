#include "sqe.h"

void *socks = NULL;

#ifdef WITH_KQUEUE
int kq = -1;
#endif
#ifdef WITH_EPOLL
int ep = -1;
#endif

struct socket_info *
new_socket_info(int fd)
{
	struct socket_info *si, **slot;

	si = malloc(sizeof(*si));
	if (!si)
		croak(1, "new_socket_info: malloc(socket_info)");
	bzero(si, sizeof(*si));
	si->fd = fd;
	TAILQ_INIT(&si->send_bufs);
	JLI(slot, socks, fd);
	if (slot == PJERR)
		croak(2, "new_socket_info: JLI failed");
	if (*slot)
		croak(3, "new_socket_info: assertion failed, fd %d is already there", fd);
	*slot = si;
	return si;
}

static void
flush_buffers(struct socket_info *si)
{
	struct iovec *io;
	struct send_buf *sb;
	int i, n;

	/* XXX handle cases where there is nothing, and where there is only one */
	io = malloc(sizeof(*io) * si->n_send_bufs);
	if (!io)
		croak(1, "flush_buffers: malloc(iovec)");
	i = 0;
	TAILQ_FOREACH(sb, &si->send_bufs, send_list) {
		io[i].iov_base = sb->buf + sb->offset;
		io[i].iov_len  = sb->size;
		i++;
	}
fprintf(stderr, "writeving %d iovectors to fd %d\n", i, si->fd);
	if ( (n = writev(si->fd, io, i)) < 0)
		croak(1, "flush_buffers: writev");
fprintf(stderr, "writev: %d bytes\n", n);
	free(io);
	while (n > 0) {
		sb = TAILQ_FIRST(&si->send_bufs);
		if (!sb)
			croakx(2, "flush_buffers: send_bufs queue unexpectedly empty");
		if (n >= sb->size) {
			TAILQ_REMOVE(&si->send_bufs, sb, send_list);
			n -= sb->size;
			free(sb->buf);
			free(sb);
			si->n_send_bufs--;
		} else {
			sb->size   -= n;
			sb->offset += n;
			n = 0;
		}
	}
	if (TAILQ_EMPTY(&si->send_bufs)) {
		on_write(si, NULL);
	}
	//if (write(fd, buf, size) < 0)
	//	croak(1, "tcp_send: write");
}

void
tcp_send(struct socket_info *si, void *buf, int size)
{
	struct send_buf *sb;
	/* XXX in reality, try to send something right away */
	sb = malloc(sizeof(*sb));
	if (!sb)
		croak(1, "tcp_send: malloc(send_buf)");
	bzero(sb, sizeof(*sb));
	sb->buf = malloc(size);
	if (!sb->buf)
		croak(1, "tcp_send: malloc(sb->buf)");
	sb->size = size;
	sb->offset = 0;
	memcpy(sb->buf, buf, size);
	if (TAILQ_EMPTY(&si->send_bufs)) {
		on_write(si, flush_buffers);
	}
	TAILQ_INSERT_TAIL(&si->send_bufs, sb, send_list);
	si->n_send_bufs++;
}

void
delete_socket_info(struct socket_info *si)
{
	int rc;
	struct send_buf *n1, *n2;

	n1 = TAILQ_FIRST(&si->send_bufs);
	while (n1 != NULL) {
		n2 = TAILQ_NEXT(n1, send_list);
		free(n1->buf);
		free(n1);
		n1 = n2;
	}
	TAILQ_INIT(&si->send_bufs);
	si->n_send_bufs = 0;

	JLD(rc, socks, si->fd);
	close(si->fd);
	free(si);
}

#ifdef WITH_EPOLL
static void
set_handlers(struct socket_info *si,
			 void (*read_handler)(struct socket_info *si),
			 void (*write_handler)(struct socket_info *si))
{
	struct epoll_event set_ev;
	int op;
	int was_monitored = 0;

	if (ep < 0) {
		if ( (ep = epoll_create(10)) < 0)
			croak(1, "set_handlers: epoll_create");
	}

	if (si->read_handler || si->write_handler) {
		was_monitored = 1;
	}
	si->read_handler  = read_handler;
	si->write_handler = write_handler;
	set_ev.events = 0;
	if (si->read_handler)
		set_ev.events |= EPOLLIN;
	if (si->write_handler)
		set_ev.events |= EPOLLOUT;
	if (was_monitored) {
		if (set_ev.events)
			op = EPOLL_CTL_MOD;
		else
			op = EPOLL_CTL_DEL;
	} else {
		if (set_ev.events)
			op = EPOLL_CTL_ADD;
		else
			return;
	}

	set_ev.data.fd = si->fd;
	if (epoll_ctl(ep, op, si->fd, &set_ev) < 0)
		croak(1, "set_handlers: epoll_ctl");
}
#endif

void
binary_dump(FILE *f, void *buf, int len)
{
	unsigned char *s = buf;
	int i;

	for (i = 0; i < len; i++) {
		fprintf(f, "%02x ", (unsigned)s[i]);
		if (i % 16 == 15 && i < len-1) {
			int j;
			fprintf(f, "  ");
			for (j = i - 16; j <= i; j++) {
				fprintf(f, "%c", isprint(s[j]) ? s[j] : '.');
			}
			fprintf(f, "\n");
		}
	}
	fprintf(f, "\n");
}

void
on_read(struct socket_info *si, void (*read_handler)(struct socket_info *si))
{
#ifdef WITH_KQUEUE
	si->read_handler = read_handler;
	if (kq < 0) {
		if ( (kq = kqueue()) < 0)
			croak(1, "on_read: kqueue");
	}
	{
		struct kevent set_ke, get_ke;
		int nev;
		unsigned flags = EV_ADD | EV_RECEIPT;

		flags |= read_handler ? EV_ENABLE : EV_DISABLE;
		EV_SET(&set_ke, si->fd, EVFILT_READ, flags, 0, 0, 0);

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
#ifdef WITH_EPOLL
	set_handlers(si, read_handler, si->write_handler);
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
		unsigned flags = EV_ADD | EV_RECEIPT;

		flags |= write_handler ? EV_ENABLE : EV_DISABLE;
		EV_SET(&set_ke, si->fd, EVFILT_WRITE, flags, 0, 0, 0);

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
#ifdef WITH_EPOLL
	set_handlers(si, si->read_handler, write_handler);
#endif
}

#ifdef WITH_KQUEUE
void
event_loop(void)
{
	struct kevent ke[10];
	int nev, i, ms;
	struct timespec to;
	while (1) {
		ms = sid_next_timeout();
		to.tv_sec = ms / 1000;
		to.tv_nsec = (ms % 1000)*1000000;
		nev = kevent(kq, NULL, 0, ke, 10, &to);
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
		check_timed_out_requests();
	}
}
#endif
#ifdef WITH_EPOLL
void
event_loop(void)
{
	struct epoll_event ev[10];
	int nev, i, ms;
	while (1) {
		ms = sid_next_timeout();
		nev = epoll_wait(ep, ev, 10, ms);
		if (nev < 0)
			croak(1, "event_loop: epoll_wait");
		for (i = 0; i < nev; i++) {
			struct socket_info *si, **slot;

			if ((ev[i].events & EPOLLIN)) {
				JLG(slot, socks, ev[i].data.fd);
				if (slot && *slot) {
					si = *slot;
					if (si->read_handler) {
						si->read_handler(si);
					} else {
						fprintf(stderr, "event_loop: EPOLLIN: fd %u - socket does not have a read handler\n", (unsigned)ev[i].data.fd);
					}
				} else {
					fprintf(stderr, "event_loop: EPOLLIN: fd %u - no FD found in socks\n", (unsigned)ev[i].data.fd);
				}
			}
			if ((ev[i].events & EPOLLOUT)) {
				JLG(slot, socks, ev[i].data.fd);
				if (slot && *slot) {
					si = *slot;
					if (si->write_handler) {
						si->write_handler(si);
					} else {
						fprintf(stderr, "event_loop: EPOLLOUT: fd %u - socket does not have a write handler\n", (unsigned)ev[i].data.fd);
					}
				} else {
					fprintf(stderr, "event_loop: EPOLLOUT: fd %u - no FD found in socks\n", (unsigned)ev[i].data.fd);
				}
			}
			if (!(ev[i].events & (EPOLLIN|EPOLLOUT))) {
				fprintf(stderr, "event_loop: unexpected event 0x%x, fd %u\n", ev[i].events, (unsigned)ev[i].data.fd);
			}
		}
		check_timed_out_requests();
	}
}
#endif
