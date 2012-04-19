#include "sqe.h"

static struct socket_info *snmp = NULL;

static void
snmp_receive(struct socket_info *snmp)
{
	struct sockaddr_in from;
	socklen_t len;
	char buf[65000];
	int n;
	struct encode enc, *e;
	unsigned char t;
	unsigned l;
	unsigned sid;
	char *trace;
	struct destination *dest;
	struct sid_info *si;

	/* XXX if several datagrams are ready we need a good way to bypass another
	 * kevent/epoll_wait call after reading only one of them. */
	len = sizeof(from);
	if ( (n = recvfrom(snmp->fd, buf, 65000, 0, (struct sockaddr *)&from, &len)) < 0)
		croak(1, "snmp_receive: recvfrom");
fprintf(stderr, "got UDP datagram (%d bytes) from %s:%d\n", n, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
dump_buf(stderr, buf, n);

	dest = find_destination(&from.sin_addr, ntohs(from.sin_port));
	if (!dest) {
		fprintf(stderr, "destination %s:%d is not knowing, ignoring packet\n", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
		return;
	}

	enc = encode_init(buf, n); e = &enc;

	#define CHECK(prob, val) if ((val) < 0) { trace = prob; goto bad_snmp_packet; }
	trace = "start sequence type/len";
	if (decode_type_len(e, &t, &l) < 0)	goto bad_snmp_packet;
	trace = "start sequence type";
	if (t != AT_SEQUENCE)	goto bad_snmp_packet;

	CHECK("decoding version", decode_integer(e, -1, NULL));

	trace = "community type/len";
	if (decode_type_len(e, &t, &l) < 0)	goto bad_snmp_packet;
	trace = "community type";
	if (t != AT_STRING)	goto bad_snmp_packet;
	e->b += l;  e->len += l;  // XXX skip community

	trace = "PDU type/len";
	if (decode_type_len(e, &t, &l) < 0)	goto bad_snmp_packet;
	trace = "PDU type";
	if (t != PDU_GET_RESPONSE)	goto bad_snmp_packet;

	CHECK("decoding request id", decode_integer(e, -1, &sid));
	#undef CHECK

	si = find_sid_info(dest, sid);
	if (!si) {
		fprintf(stderr, "unable to find sid_info with sid %u, ignoring packet\n", sid);
		return;
	}

	fprintf(stderr, "this packet appears to be legit, sid %u(%u)\n", sid, si->sid);
	process_sid_info_response(si, e);

	return;

bad_snmp_packet:
	fprintf(stderr, "bad SNMP packet, ignoring: %s\n", trace);
}

void
create_snmp_socket(void)
{
	int fd;
	int n;

	if (snmp)
		croakx(1, "create_snmp_socket: socket already exists");

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		croak(1, "create_snmp_socket: socket");

	/* try a very large receive buffer size */
	n = 10 * 1024 * 1024;
	while (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n)) < 0)
		n /= 2;

	snmp = new_socket_info(fd);
	on_read(snmp, snmp_receive);
}

void snmp_send(struct destination *dest, struct encode *packet)
{
	if (sendto(snmp->fd, packet->buf, packet->len, 0, (struct sockaddr *)&dest->dest_addr, sizeof(dest->dest_addr)) != packet->len)
		croak(1, "snmp_send: sendto");
fprintf(stderr, "UDP datagram of %d bytes sent to %s:%d\n", packet->len, inet_ntoa(dest->dest_addr.sin_addr), ntohs(dest->dest_addr.sin_port));
}
