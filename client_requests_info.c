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
fprintf(stderr, "insert fd %d\n", fd);
	JLI(ip_slot, *fd_slot, ip->s_addr);
	if (ip_slot == PJERR)
		croak(2, "get_client_requests_info: JLI(ip) failed");
	JLI(cri_slot, *ip_slot, port);
	if (cri_slot == PJERR)
		croak(2, "get_client_requests_info: JLI(port) failed");
	if (!*cri_slot) {
fprintf(stderr, "insert new cri %d-%d-%d\n", fd, ip->s_addr, port);
		cri = malloc(sizeof(*cri));
		if (!cri)
			croak(2, "get_client_requests_info: malloc(cri)");
		bzero(cri, sizeof(*cri));
		cri->dest = dest;
		cri->fd   = fd;
		TAILQ_INIT(&cri->oids_to_query);
		TAILQ_INIT(&cri->sid_infos);
		*cri_slot = cri;
	}

	JLI(dest_cri_slot, dest->client_requests_info, fd);
	if (dest_cri_slot == PJERR)
		croak(2, "get_client_requests_info: JLI(dest/fd) failed");
	*dest_cri_slot = *cri_slot;
	return *cri_slot;
}

int
free_all_client_request_info_for_fd(int fd)
{
	void **fd_slot, **ip_slot;
	struct client_requests_info **cri_slot;
	Word_t ip, port;
	Word_t rc;

fprintf(stderr, "free_all_client_request_info_for_fd(%d)\n", fd);
	JLG(fd_slot, dest_by_fd, fd);
	if (fd_slot == PJERR)
		croak(2, "free_all_client_request_info_for_fd: JLG(fd) failed");
	if (!fd_slot)
		return 1;

	ip = 0;
	JLF(ip_slot, *fd_slot, ip);
	while (ip_slot) {
		port = 0;
		JLF(cri_slot, *ip_slot, port);
		while (cri_slot) {
			fprintf(stderr, "free_all_client_request_info_for_fd(%d), %s:%u\n",
					fd, inet_ntoa((*cri_slot)->dest->ip), (*cri_slot)->dest->port);
			free_client_request_info(*cri_slot);
			JLN(cri_slot, *ip_slot, port);
		}
		JLFA(rc, *ip_slot);
		JLN(ip_slot, *fd_slot, ip);
	}
	JLFA(rc, *fd_slot);
	JLD(rc, dest_by_fd, fd);
	return 1;
}

int
free_client_request_info(struct client_requests_info *cri)
{
	struct cid_info **ci_slot;
	Word_t cid;
	Word_t rc;
	struct sid_info *si, *si_temp;

fprintf(stderr, "freeing client_requests_info, fd %d\n", cri->fd);

	si = TAILQ_FIRST(&cri->sid_infos);
	while (si != NULL) {
		si_temp = TAILQ_NEXT(si, sid_list);
		free_sid_info(si);
		si = si_temp;
	}
	TAILQ_INIT(&cri->sid_infos);

fprintf(stderr, "   oids_to_query, fd %d\n", cri->fd);
	free_oid_info_list(&cri->oids_to_query);
	cid = 0;
	JLF(ci_slot, cri->cid_info, cid);
	while (ci_slot) {
		free_cid_info(*ci_slot, cri->dest);
		JLN(ci_slot, cri->cid_info, cid);
	}
	JLFA(rc, cri->cid_info);
	JLD(rc, cri->dest->client_requests_info, cri->fd);
	free(cri);
	return 1;
}

