#include "sqe.h"

JudyL by_ip;

struct destination *get_destination(struct in_addr *ip, unsigned port)
{
	void **ip_slot;
	struct destination **dest_slot, *d;

	JLI(ip_slot, by_ip, ip->s_addr);
	if (ip_slot == PJERR)
		croak(2, "get_destination: JLI failed");
	JLI(dest_slot, *ip_slot, port);
	if (dest_slot == PJERR)
		croak(2, "get_destination: JLI failed");
	if (!*dest_slot) {
		d = malloc(sizeof(*d));
		if (!d)
			croak(2, "get_destination: malloc(destination)");
		bzero(d, sizeof(*d));
		d->ip                      = *ip;
		d->port                    = port;
		d->version                 = 1; /* 2c is the default */
		strcpy(d->community, "public");
		d->dest_addr.sin_family    = PF_INET;
		d->dest_addr.sin_addr      = *ip;
		d->dest_addr.sin_port      = htons(port);
		d->max_packets_on_the_wire = DEFAULT_MAX_PACKETS_ON_THE_WIRE;
		d->max_request_packet_size = DEFAULT_MAX_REQUEST_PACKET_SIZE;
		d->timeout                 = DEFAULT_TIMEOUT;
		d->retries                 = DEFAULT_RETRIES;
		d->min_interval            = DEFAULT_MIN_INTERVAL;
		d->request_delay           = DEFAULT_REQUEST_DELAY;
		*dest_slot = d;
	}
	return *dest_slot;
}

struct destination *find_destination(struct in_addr *ip, unsigned port)
{
	void **ip_slot;
	struct destination **dest_slot;

	JLG(ip_slot, by_ip, ip->s_addr);
	if (ip_slot == PJERR || !ip_slot) return NULL;

	JLG(dest_slot, *ip_slot, port);
	if (dest_slot == PJERR || !dest_slot) return NULL;
	return *dest_slot;
}

void
maybe_query_destination(struct destination *dest)
{
	struct client_requests_info **cri_slot;
	Word_t fd;

	/* XXX first check whether anything can be sent */

	/* Then find a client_requests_info, in a round-robin fashion,
	 * which has anything to send.   Be careful with when to stop.
	 */
	fd = dest->fd_of_last_query;
again:
fprintf(stderr, "maybe %d\n", (int)fd);
	JLN(cri_slot, dest->client_requests_info, fd);
	if (dest->fd_of_last_query == 0)
		dest->fd_of_last_query = fd;
	if (!cri_slot) {
		fd = 0;
		JLF(cri_slot, dest->client_requests_info, fd);
		if (!cri_slot) return;  /* no clients for this destination */
	}
	if (cri_can_send(*cri_slot))
		build_snmp_query(*cri_slot);
	else if (fd != dest->fd_of_last_query)
		goto again;
	dest->fd_of_last_query = fd;
	// XXX goto
}

void
destination_timer(struct destination *dest)
{
	// XXX implement me
	// destination_stop_timing(dest);
}
