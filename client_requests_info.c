#include "sqe.h"

static JudyL dest_by_fd;  // -> JudyL(by ip) -> JudyL(by port) -> destination

struct client_requests_info *
get_client_requests_info(struct in_addr *ip, unsigned port, int fd)
{
	struct destination *dest;
	void **fd_slot, **ip_slot;
	struct client_requests_info **cri_slot, **dest_cri_slot, *cri;

	dest = get_destination(ip, port);

	JLI(fd_slot, dest_by_fd, fd);
	if (fd_slot == PJERR)
		croak(2, "get_client_requests_info: JLI(fd) failed");
	JLI(ip_slot, *fd_slot, ip->s_addr);
	if (ip_slot == PJERR)
		croak(2, "get_client_requests_info: JLI(ip) failed");
	JLI(cri_slot, *ip_slot, port);
	if (cri_slot == PJERR)
		croak(2, "get_client_requests_info: JLI(port) failed");
	if (!*cri_slot) {
		cri = malloc(sizeof(*cri));
		if (!cri)
			croak(2, "get_client_requests_info: malloc(cri)");
		bzero(cri, sizeof(*cri));
		cri->dest = dest;
		cri->fd   = fd;
		TAILQ_INIT(&cri->oids_to_query);
		*cri_slot = cri;
	}

	JLI(dest_cri_slot, dest->client_requests_info, fd);
	if (dest_cri_slot == PJERR)
		croak(2, "get_client_requests_info: JLI(dest/fd) failed");
	*dest_cri_slot = *cri_slot;
	return *cri_slot;
}
