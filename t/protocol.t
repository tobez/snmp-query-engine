#! /usr/bin/perl
# ABOUTME: Tests the client protocol surface of snmp-query-engine: option
# ABOUTME: get/set, request validation errors, info stats shape. No SNMP agent needed.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;
use SQE::Test ':all';

my $d = spawn_daemon();
my $NUMBER = qr/^\d+$/;

my $version_output = `$FindBin::Bin/../snmp-query-engine -v`;
like($version_output, qr/^snmp-query-engine \d+\.\d+\.\d+$/, "-v prints semantic version");

my @GLOBAL_STATS = qw(
active_cid_infos
active_client_connections
active_cr_infos
active_oid_infos
active_sid_infos
active_timers_sec
active_timers_usec
bad_snmp_responses
client_requests
destination_ignores
destination_throttles
get_requests
getopt_requests
gettable_requests
global_throttles
good_snmp_responses
info_requests
invalid_requests
max_packets_on_the_wire
oids_ignored
oids_non_increasing
oids_requested
oids_returned_from_snmp
oids_returned_to_client
octets_received
octets_sent
packets_on_the_wire
setopt_requests
snmp_retries
snmp_sends
snmp_timeouts
snmp_v1_sends
snmp_v2c_sends
total_cid_infos
total_client_connections
total_cr_infos
total_oid_infos
total_sid_infos
total_timers_sec
total_timers_usec
udp_receive_buffer_size
udp_send_buffer_size
udp_send_buffer_overflow
udp_timeouts
uptime
program_version
);

my @CLIENT_STATS = qw(
active_cid_infos
active_cr_infos
active_sid_infos
client_requests
get_requests
getopt_requests
gettable_requests
good_snmp_responses
info_requests
invalid_requests
oids_non_increasing
oids_requested
oids_returned_from_snmp
oids_returned_to_client
setopt_requests
snmp_retries
snmp_sends
snmp_timeouts
snmp_v1_sends
snmp_v2c_sends
total_cid_infos
total_cr_infos
total_sid_infos
udp_timeouts
uptime
);
my %CLIENT_STATS = map { $_ => $NUMBER } @CLIENT_STATS;
my %GLOBAL_STATS = map { $_ => $NUMBER } @GLOBAL_STATS;
$CLIENT_STATS{oids_non_increasing} = 0;
$GLOBAL_STATS{oids_non_increasing} = 0;
$GLOBAL_STATS{version} = qr/^\d+\.\d+\.\d+$/;

$d->mp->utf8(1);
request_match($d, "defaults via getopt", [RT_GETOPT,2000,"127.0.0.1",161], [RT_GETOPT|RT_REPLY,2000,
	{ip=>"127.0.0.1", port=>161, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 2000, retries => 3, min_interval => 10, max_repetitions => 10, ignore_threshold => 0, ignore_duration => 300000, max_reply_size => 1472, estimated_value_size => 9, max_oids_per_request => 64 }]);
$d->mp->utf8(0);
request_match($d, "defaults via setopt", [RT_SETOPT,2001,"127.0.0.1",161, {}], [RT_SETOPT|RT_REPLY,2001,
	{ip=>"127.0.0.1", port=>161, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 2000, retries => 3, min_interval => 10, max_repetitions => 10, ignore_threshold => 0, ignore_duration => 300000, max_reply_size => 1472, estimated_value_size => 9, max_oids_per_request => 64 }]);
request_match($d, "setopt bad length", [RT_SETOPT,2002,"127.0.0.1",161], [RT_SETOPT|RT_ERROR,2002,qr/bad request length/]);
request_match($d, "setopt bad port 1", [RT_SETOPT,2003,"127.0.0.1","x",{}], [RT_SETOPT|RT_ERROR,2003,qr/bad port number/]);
request_match($d, "setopt bad port 2", [RT_SETOPT,2004,"127.0.0.1",80000,{}], [RT_SETOPT|RT_ERROR,2004,qr/bad port number/]);
request_match($d, "setopt bad IP", [RT_SETOPT,2005,"127.260.0.1",161,{}], [RT_SETOPT|RT_ERROR,2005,qr/bad IP/]);
request_match($d, "setopt opt not map 1", [RT_SETOPT,2006,"127.0.0.1",161,[]], [RT_SETOPT|RT_ERROR,2006,qr/not a map/]);
request_match($d, "setopt opt not map 2", [RT_SETOPT,2007,"127.0.0.1",161,42], [RT_SETOPT|RT_ERROR,2007,qr/not a map/]);
request_match($d, "setopt bad option key", [RT_SETOPT,2008,"127.0.0.1",161,{meow=>1}], [RT_SETOPT|RT_ERROR,2008,qr/bad option key/]);
request_match($d, "setopt bad version 1", [RT_SETOPT,2009,"127.0.0.1",161,{version=>42}], [RT_SETOPT|RT_ERROR,2009,qr/invalid SNMP version/]);
request_match($d, "setopt bad version 2", [RT_SETOPT,2010,"127.0.0.1",161,{version=>"x"}], [RT_SETOPT|RT_ERROR,2010,qr/invalid SNMP version/]);
request_match($d, "setopt bad community", [RT_SETOPT,2011,"127.0.0.1",161,{community=>[]}], [RT_SETOPT|RT_ERROR,2011,qr/invalid SNMP community/]);
request_match($d, "setopt bad max_packets 1", [RT_SETOPT,2012,"127.0.0.1",161,{max_packets=>"meow"}], [RT_SETOPT|RT_ERROR,2012,qr/invalid max packets/]);
request_match($d, "setopt bad max_packets 2", [RT_SETOPT,2013,"127.0.0.1",161,{max_packets=>0}], [RT_SETOPT|RT_ERROR,2013,qr/invalid max packets/]);
request_match($d, "setopt bad max_packets 3", [RT_SETOPT,2014,"127.0.0.1",161,{max_packets=>30000}], [RT_SETOPT|RT_ERROR,2014,qr/invalid max packets/]);
request_match($d, "setopt bad global_max_packets 1", [RT_SETOPT,42012,"127.0.0.1",161,{global_max_packets=>"meow"}], [RT_SETOPT|RT_ERROR,42012,qr/invalid global max packets/]);
request_match($d, "setopt bad global_max_packets 2", [RT_SETOPT,42013,"127.0.0.1",161,{global_max_packets=>0}], [RT_SETOPT|RT_ERROR,42013,qr/invalid global max packets/]);
request_match($d, "setopt bad global_max_packets 3", [RT_SETOPT,42014,"127.0.0.1",161,{global_max_packets=>3000000}], [RT_SETOPT|RT_ERROR,42014,qr/invalid global max packets/]);
request_match($d, "setopt bad max req size 1", [RT_SETOPT,2015,"127.0.0.1",161,{max_req_size=>"foo"}], [RT_SETOPT|RT_ERROR,2015,qr/invalid max request size/]);
request_match($d, "setopt bad max req size 2", [RT_SETOPT,2016,"127.0.0.1",161,{max_req_size=>480}], [RT_SETOPT|RT_ERROR,2016,qr/invalid max request size/]);
request_match($d, "setopt bad max req size 3", [RT_SETOPT,2017,"127.0.0.1",161,{max_req_size=>52000}], [RT_SETOPT|RT_ERROR,2017,qr/invalid max request size/]);
request_match($d, "setopt bad timeout 1", [RT_SETOPT,2018,"127.0.0.1",161,{timeout=>"st"}], [RT_SETOPT|RT_ERROR,2018,qr/invalid timeout/]);
request_match($d, "setopt bad timeout 2", [RT_SETOPT,2019,"127.0.0.1",161,{timeout=>31000}], [RT_SETOPT|RT_ERROR,2019,qr/invalid timeout/]);
request_match($d, "setopt bad retries 1", [RT_SETOPT,2020,"127.0.0.1",161,{retries=>"foo"}], [RT_SETOPT|RT_ERROR,2020,qr/invalid retries/]);
request_match($d, "setopt bad retries 2", [RT_SETOPT,2021,"127.0.0.1",161,{retries=>0}], [RT_SETOPT|RT_ERROR,2021,qr/invalid retries/]);
request_match($d, "setopt bad retries 3", [RT_SETOPT,2022,"127.0.0.1",161,{retries=>12}], [RT_SETOPT|RT_ERROR,2022,qr/invalid retries/]);
request_match($d, "setopt bad min interval 1", [RT_SETOPT,2120,"127.0.0.1",161,{min_interval=>"foo"}], [RT_SETOPT|RT_ERROR,2120,qr/invalid min interval/]);
request_match($d, "setopt bad min interval 2", [RT_SETOPT,2122,"127.0.0.1",161,{min_interval=>10002}], [RT_SETOPT|RT_ERROR,2122,qr/invalid min interval/]);
request_match($d, "setopt bad max repetitions 1", [RT_SETOPT,2220,"127.0.0.1",161,{max_repetitions=>"foo"}], [RT_SETOPT|RT_ERROR,2220,qr/invalid max repetitions/]);
request_match($d, "setopt bad max repetitions 2", [RT_SETOPT,2221,"127.0.0.1",161,{max_repetitions=>0}], [RT_SETOPT|RT_ERROR,2221,qr/invalid max repetitions/]);
request_match($d, "setopt bad max repetitions 3", [RT_SETOPT,2222,"127.0.0.1",161,{max_repetitions=>256}], [RT_SETOPT|RT_ERROR,2222,qr/invalid max repetitions/]);
request_match($d, "setopt bad max repetitions 4", [RT_SETOPT,2223,"127.0.0.1",161,{max_repetitions=>128}], [RT_SETOPT|RT_ERROR,2223,qr/invalid max repetitions/]);
request_match($d, "gettable bad max repetitions", [RT_GETTABLE,2224,"127.0.0.1",161,"1.3.6.1.2.1.1.9.1.2",128], [RT_GETTABLE|RT_ERROR,2224,qr/bad max repetitions/]);
request_match($d, "setopt bad engineid 1", [RT_SETOPT,2230,"127.0.0.1",161,{engineid=>"zz"}], [RT_SETOPT|RT_ERROR,2230,qr/invalid engineid hexstring/]);
request_match($d, "setopt bad engineid 2", [RT_SETOPT,2231,"127.0.0.1",161,{engineid=>"800"}], [RT_SETOPT|RT_ERROR,2231,qr/invalid engineid hexstring/]);
request_match($d, "setopt bad engineid 3", [RT_SETOPT,2232,"127.0.0.1",161,{engineid=>"ab" x 65}], [RT_SETOPT|RT_ERROR,2232,qr/invalid engineid hexstring/]);
request_match($d, "setopt bad authkul 1", [RT_SETOPT,2233,"127.0.0.1",161,{authkul=>"zz"}], [RT_SETOPT|RT_ERROR,2233,qr/invalid authkul hexstring/]);
request_match($d, "setopt bad authkul 2", [RT_SETOPT,2234,"127.0.0.1",161,{authkul=>"abc"}], [RT_SETOPT|RT_ERROR,2234,qr/invalid authkul hexstring/]);
request_match($d, "setopt bad privkul 1", [RT_SETOPT,2235,"127.0.0.1",161,{privkul=>"zz"}], [RT_SETOPT|RT_ERROR,2235,qr/invalid privkul hexstring/]);
request_match($d, "setopt bad privkul 2", [RT_SETOPT,2236,"127.0.0.1",161,{privkul=>"ab" x 65}], [RT_SETOPT|RT_ERROR,2236,qr/invalid privkul hexstring/]);
request_match($d, "setopt empty engineid", [RT_SETOPT,2237,"127.0.0.1",161,{engineid=>""}], [RT_SETOPT|RT_ERROR,2237,qr/invalid engineid hexstring/]);
request_match($d, "setopt blank engineid", [RT_SETOPT,2238,"127.0.0.1",161,{engineid=>" "}], [RT_SETOPT|RT_ERROR,2238,qr/invalid engineid hexstring/]);
request_match($d, "setopt empty authkul", [RT_SETOPT,2239,"127.0.0.1",161,{authkul=>""}], [RT_SETOPT|RT_ERROR,2239,qr/invalid authkul hexstring/]);
request_match($d, "setopt empty privkul", [RT_SETOPT,2240,"127.0.0.1",161,{privkul=>""}], [RT_SETOPT|RT_ERROR,2240,qr/invalid privkul hexstring/]);
request_match($d, "setopt empty username", [RT_SETOPT,2241,"127.0.0.1",161,{username=>""}], [RT_SETOPT|RT_ERROR,2241,qr/invalid username/]);
request_match($d, "setopt empty authpassword", [RT_SETOPT,2242,"127.0.0.1",161,{authpassword=>""}], [RT_SETOPT|RT_ERROR,2242,qr/invalid auth password/]);
request_match($d, "setopt empty privpassword", [RT_SETOPT,2243,"127.0.0.1",161,{privpassword=>""}], [RT_SETOPT|RT_ERROR,2243,qr/invalid priv password/]);

my $kul32 = "ab" x 32;
my $kul20 = "cd" x 20;
my $v3eid = "0a0b0c0d0e";
request_match($d, "setopt authkul without authprotocol", [RT_SETOPT,2244,"127.0.0.1",1610,{engineid=>$v3eid, username=>"u", authkul=>$kul32}], [RT_SETOPT|RT_ERROR,2244,qr{authprotocol is required with authkul/privkul}]);
request_match($d, "setopt privkul without authprotocol", [RT_SETOPT,2245,"127.0.0.1",1610,{engineid=>$v3eid, username=>"u", privprotocol=>"aes", privkul=>$kul32}], [RT_SETOPT|RT_ERROR,2245,qr{authprotocol is required with authkul/privkul}]);
request_match($d, "setopt authkul wrong length", [RT_SETOPT,2246,"127.0.0.1",1610,{engineid=>$v3eid, username=>"u", authprotocol=>"sha256", authkul=>$kul20}], [RT_SETOPT|RT_ERROR,2246,qr/authkul length does not match auth protocol/]);
request_match($d, "setopt privkul wrong length", [RT_SETOPT,2247,"127.0.0.1",1610,{engineid=>$v3eid, username=>"u", authprotocol=>"sha256", authkul=>$kul32, privprotocol=>"aes", privkul=>$kul20}], [RT_SETOPT|RT_ERROR,2247,qr/privkul length does not match auth protocol/]);
request_match($d, "setopt privkul without privprotocol", [RT_SETOPT,2248,"127.0.0.1",1610,{engineid=>$v3eid, username=>"u", authprotocol=>"sha256", authkul=>$kul32, privkul=>$kul32}], [RT_SETOPT|RT_ERROR,2248,qr/privprotocol is required with privkul/]);
request_match($d, "setopt correct kuls accepted", [RT_SETOPT,2249,"127.0.0.1",1610,{engineid=>$v3eid, username=>"u", authprotocol=>"sha256", authkul=>$kul32, privprotocol=>"aes", privkul=>$kul32}], [RT_SETOPT|RT_REPLY,2249,{engineid=>$v3eid, authkul=>$kul32, privkul=>$kul32}]);

request_match($d, "defaults unchanged", [RT_SETOPT,2023,"127.0.0.1",161, {}], [RT_SETOPT|RT_REPLY,2023,
	{ip=>"127.0.0.1", port=>161, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 2000, retries => 3, min_interval => 10, max_repetitions => 10, }]);
request_match($d, "change timeout", [RT_SETOPT,2024,"127.0.0.1",161, {timeout=>1500}], [RT_SETOPT|RT_REPLY,2024,
	{ip=>"127.0.0.1", port=>161, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 1500, retries => 3, min_interval => 10, max_repetitions => 10, }]);
request_match($d, "correct timeout via getopt", [RT_GETOPT,2025,"127.0.0.1",161], [RT_GETOPT|RT_REPLY,2025,
	{ip=>"127.0.0.1", port=>161, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 1500, retries => 3, min_interval => 10, max_repetitions => 10, }]);

request_match($d, "bad request: not an array 1", {x=>1}, [RT_ERROR,0,qr/not an array/]);
request_match($d, "bad request: not an array 2", 55, [RT_ERROR,0,qr/not an array/]);
request_match($d, "bad request: not an array 3", "hello", [RT_ERROR,0,qr/not an array/]);
request_match($d, "bad request: empty array", [], [RT_ERROR,0,qr/empty array/]);
request_match($d, "bad request: no id", [RT_GET], [RT_ERROR,0,qr/without an id/]);
request_match($d, "bad request: bad id 1", [RT_GET,-1], [RT_ERROR,0,qr/id is not a positive integer/]);
request_match($d, "bad request: bad id 2", [RT_GET,"heps"], [RT_ERROR,0,qr/id is not a positive integer/]);
request_match($d, "bad request: bad type 1", [-1,12], [RT_ERROR,12,qr/type is not a positive integer/]);
request_match($d, "bad request: bad type 2", ["heps",13], [RT_ERROR,13,qr/type is not a positive integer/]);
request_match($d, "bad request: unknown type", [9,14], [RT_ERROR|9,14,qr/unknown request type/i]);
request_match($d, "bad request length 1", [RT_GET,15,"127.0.0.1",161, 2, "public"], [RT_GET|RT_ERROR,15,qr/bad request length/i]);
request_match($d, "bad request length 2", [RT_GET,16,"127.0.0.1",161, 2, "public", ["1.3.6.1.2.1.1.5.0"], "heh", "heh"],
			  [RT_GET|RT_ERROR,16,qr/bad request length/i]);
request_match($d, "bad port number #1", [RT_GET,17,"127.0.0.1",-2, ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,17,qr/bad port number/i]);
request_match($d, "bad port number #2", [RT_GET,18,"127.0.0.1",[], ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,18,qr/bad port number/i]);
request_match($d, "bad port number #3", [RT_GET,19,"127.0.0.1",66666, ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,19,qr/bad port number/i]);
request_match($d, "bad IP 1", [RT_GET,21,666,161, ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,21,qr/bad IP/i]);
request_match($d, "bad IP 2", [RT_GET,22,[],161, ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,22,qr/bad IP/i]);
request_match($d, "bad IP 3", [RT_GET,23,"257.12.22.13",161, ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,23,qr/bad IP/i]);
request_match($d, "oids is not an array 1", [RT_GET,24,"127.0.0.1",161, 42], [RT_GET|RT_ERROR,24,qr/oids must be an array/i]);
request_match($d, "oids is not an array 2", [RT_GET,25,"127.0.0.1",161, {}], [RT_GET|RT_ERROR,25,qr/oids must be an array/i]);
request_match($d, "oids is not an array 3", [RT_GET,26,"127.0.0.1",161, "oids"], [RT_GET|RT_ERROR,26,qr/oids must be an array/i]);
request_match($d, "oids is an empty array", [RT_GET,27,"127.0.0.1",161, []], [RT_GET|RT_ERROR,27,qr/oids is an empty array/i]);

request_match($d, "destinfo length 1", [RT_DEST_INFO,6600], [RT_DEST_INFO|RT_ERROR, 6600, qr/bad request length/i]);
request_match($d, "destinfo length 2", [RT_DEST_INFO,6600,"127.0.0.1"], [RT_DEST_INFO|RT_ERROR, 6600, qr/bad request length/i]);
request_match($d, "destinfo port 1", [RT_DEST_INFO,6601,"127.0.0.1",-2], [RT_DEST_INFO|RT_ERROR, 6601, qr/bad port number/i]);
request_match($d, "destinfo port 2", [RT_DEST_INFO,6602,"127.0.0.1",[]], [RT_DEST_INFO|RT_ERROR, 6602, qr/bad port number/i]);
request_match($d, "destinfo port 3", [RT_DEST_INFO,6603,"127.0.0.1",66666], [RT_DEST_INFO|RT_ERROR, 6603, qr/bad port number/i]);
request_match($d, "destinfo ip 1", [RT_DEST_INFO,6611,666,161], [RT_DEST_INFO|RT_ERROR, 6611, qr/bad IP/i]);
request_match($d, "destinfo ip 2", [RT_DEST_INFO,6612,[],161], [RT_DEST_INFO|RT_ERROR, 6612, qr/bad IP/i]);
request_match($d, "destinfo ip 3", [RT_DEST_INFO,6613,"257.12.22.13",161], [RT_DEST_INFO|RT_ERROR, 6613, qr/bad IP/i]);

request_match($d, "destinfo zero", [RT_DEST_INFO,6620,"127.0.0.1",161], [RT_DEST_INFO|RT_REPLY, 6620,
			  { octets_received => 0, octets_sent => 0}]);

my $r = request_match($d, "stats", [RT_INFO,5000], [RT_INFO|RT_REPLY,5000,
	{ connection => \%CLIENT_STATS,
	  global => \%GLOBAL_STATS}]);
ok(!exists $r->[2]{connection}{version}, "version is a global-only stat");

$d->stop;
done_testing;
