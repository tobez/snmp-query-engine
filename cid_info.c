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
		TAILQ_INIT(&ci->oids_being_queried);
		TAILQ_INIT(&ci->oids_done);
		*ci_slot = ci;
	}
	return *ci_slot;
}
