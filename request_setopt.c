#include "sqe.h"

/*
 * setopt request:
 * [ 0, $cid, $ip, $port, {options} ]
 *
 */

int
handle_setopt_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	return error_reply(si, RT_SETOPT|RT_ERROR, cid, "not implemented yet");
}
