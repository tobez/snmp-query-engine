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
