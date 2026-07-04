snmp-query-engine - multiplexing SNMP query engine

The `snmp-query-engine` daemon accepts multiple
client connections and performs SNMP queries
towards multiple destinations on behalf of its clients,
taking care of multiplexing and throttling the requests.
This allows querying large number of devices for
large amounts of SNMP information quickly,
while controlling the load on the devices
induced by multiple SNMP queries.

See `manual.mdwn` for more.

## Installation

See `INSTALL.md` for building, `make install`, and running under
systemd (Linux) or rc.d (FreeBSD).

With regard to msgpack dependency:  snmp-query-engine
requires at least msgpack 0.5.7, previous versions
have bugs.  Unfortunately, msgpack website has changed
its layout substantially, so it is not easy to find
the release source anymore.  One possibility is to
fetch 0.5.7 from http://msgpack.org/releases/cpp/msgpack-0.5.7.tar.gz

## Testing

    make test

runs the C unit tests and the Perl integration tests via `prove`.
The Perl tests need `Data::MessagePack` and `Test2::Suite` from CPAN.
No local snmpd is required. To additionally run sanity tests against a
real SNMP agent, set `SQE_REAL_SNMPD=1` (see `t/real-snmpd.t` for the
`SQE_SNMPD_*` variables that pick the target agent and credentials).
