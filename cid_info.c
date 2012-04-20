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
		ci->cri = cri;
		ci->fd = cri->fd;
		ci->cid = cid;
		TAILQ_INIT(&ci->oids_done);
		*ci_slot = ci;
	}
	return *ci_slot;
}

int
free_cid_info(struct cid_info *ci)
{
fprintf(stderr, "  freeing cid_info, fd %d, cid %u\n", ci->fd, ci->cid);
fprintf(stderr, "  n_oids(%d), n_oids_being_queried(%d), n_oids_done(%d)\n",
		ci->n_oids, ci->n_oids_being_queried, ci->n_oids_done);
fprintf(stderr, "     oids_done, fd %d, cid %u\n", ci->fd, ci->cid);
	free_oid_info_list(&ci->oids_done);
	free(ci);
	return 1;
}

void
cid_reply(struct cid_info *ci)
{
	fprintf(stderr, "cid %u reply\n", ci->cid);
}
