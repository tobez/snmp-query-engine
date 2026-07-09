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

See `INSTALL.md` for building from source, prebuilt binaries, `make
install`, and running under systemd (Linux) or rc.d (FreeBSD).

## Testing

    make test

runs the C unit tests and the Perl integration tests via `prove`.
The Perl tests need `Data::MessagePack`, `Test2::Suite`, and `Crypt::Rijndael` from CPAN.
No local snmpd is required. To additionally run sanity tests against a
real SNMP agent, set `SQE_REAL_SNMPD=1` (see `t/real-snmpd.t` for the
`SQE_SNMPD_*` variables that pick the target agent and credentials).
