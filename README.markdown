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

With regard to msgpack dependency:  snmp-query-engine
requires at least msgpack 0.5.7, previous versions
have bugs.  Unfortunately, msgpack website has changed
its layout substantially, so it is not easy to find
the release source anymore.  One possibility is to
fetch 0.5.7 from http://msgpack.org/releases/cpp/msgpack-0.5.7.tar.gz
