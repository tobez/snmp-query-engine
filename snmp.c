#include "sqe.h"

static struct socket_info *snmp = NULL;

static void
snmp_receive(struct socket_info *snmp)
{
	struct sockaddr_in from;
	socklen_t len;
	char buf[65000];
	int n;

	/* XXX if several datagrams are ready we need a good way to bypass another
	 * kevent/epoll_wait call after reading only one of them. */
	len = sizeof(from);
	if ( (n = recvfrom(snmp->fd, buf, 65000, 0, (struct sockaddr *)&from, &len)) < 0)
		croak(1, "snmp_receive: recvfrom");
fprintf(stderr, "got UDP datagram (%d bytes) from %s:%d\n", n, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	//if (n <
dump_buf(stderr, buf, n);
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
