#include "sqe.h"

struct cid_info *
get_cid_info(struct client_requests_info *cri, unsigned cid)
{
	struct cid_info **ci_slot, *ci;

	JLI(ci_slot, cri->cid_info, cid);
	if (ci_slot == PJERR)
		croak(2, "get_cid_info: JLI(cid) failed");
	if (!*ci_slot) {
		ci = malloc(sizeof(*ci));
		if (!ci)
			croak(2, "get_cid_info: malloc(cid_info)");
		bzero(ci, sizeof(*ci));
		ci->fd = cri->fd;
		ci->cid = cid;
		TAILQ_INIT(&ci->oids_done);
		*ci_slot = ci;
	}
	return *ci_slot;
}

int
free_cid_info(struct cid_info *ci, struct destination *dest)
{
fprintf(stderr, "  freeing cid_info, fd %d, cid %u\n", ci->fd, ci->cid);
fprintf(stderr, "     oids_done, fd %d, cid %u\n", ci->fd, ci->cid);
	free_oid_info_list(&ci->oids_done);
	free(ci);
	return 1;
}
