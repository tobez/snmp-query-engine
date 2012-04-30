#include "sqe.h"

/*
 * gettable request:
 * [ 0, $cid, XXX ]
 *
 */

int
handle_gettable_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	return error_reply(si, RT_GETTABLE|RT_ERROR, cid, "not implemented yet");
}
