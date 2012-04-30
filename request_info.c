#include "sqe.h"

/*
 * info request:
 * [ 0, $cid ]
 *
 */

int
handle_info_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	return error_reply(si, RT_INFO|RT_ERROR, cid, "not implemented yet");
}
