#include "sqe.h"

void *socks = NULL;

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
		croak(3, "new_socket_info: assertion failed, fd %d is already there");
	*slot = si;
	return si;
}

void
delete_socket_info(struct socket_info *si)
{
	/* XXX */
}

void
event_loop(void)
{
}
