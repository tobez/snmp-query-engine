#include "sqe.h"

/*
 * getopt request:
 * [ 0, $cid, $ip, $port ]
 *
 */

int
handle_getopt_request(struct socket_info *si, unsigned cid, msgpack_object *o)
{
	return error_reply(si, RT_GETOPT|RT_ERROR, cid, "not implemented yet");
}
