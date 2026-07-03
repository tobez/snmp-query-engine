#! /usr/bin/perl
# ABOUTME: End-to-end tests of SNMP behavior against a scriptable fake agent:
# ABOUTME: gets, table walks, timeouts, ignores, retries, malformed replies.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;
use Time::HiRes ();
use SQE::Test ':all';
use SQE::FakeAgent;

my $NUMBER   = qr/^\d+$/;
my $uptime   = qr/^\d+$/;
my $hostname = "sqe-fake";

my @tree = (
	['1.3.6.1.2.1.1.5.0',     str => $hostname],
	['1.3.6.1.2.1.2.1.0',     int => 3],
	['1.3.6.1.2.1.2.2.1.1.1', int => 1],
	['1.3.6.1.2.1.2.2.1.1.2', int => 2],
	['1.3.6.1.2.1.2.2.1.1.3', int => 3],
	['1.3.6.1.2.1.2.2.1.2.1', str => 'lo0'],
	['1.3.6.1.2.1.2.2.1.2.2', str => 'em0'],
	['1.3.6.1.2.1.2.2.1.2.3', str => 'em1'],
	['1.3.6.1.2.1.2.2.1.3.1', int => 24],     # entry after ifDescr so walks leave the column
	['1.3.6.1.2.1.25.1.1.0',  ticks => 123456],
);

my $d      = spawn_daemon();
my $agent  = SQE::FakeAgent->spawn(tree => \@tree);
my $target = "127.0.0.1";
my $port   = $agent->port;
my $r;

# 1. sanity get
request_match($d, "basic get works", [RT_GET,33,$target,$port, ["1.3.6.1.2.1.1.5.0"]],
	[RT_GET|RT_REPLY,33,[["1.3.6.1.2.1.1.5.0",$hostname]]]);

# 2. ignore machinery
request_match($d, "change community to a bad one",
	[RT_SETOPT,3000,$target,$port, {community=>1234, ignore_threshold => 1, timeout => 100, retries => 2, ignore_duration => 500}],
	[RT_SETOPT|RT_REPLY,3000,
	{ip=>$target, port=>$port, community=>1234, version=>2, max_packets => 3, max_req_size => 1400, timeout => 100, retries => 2, min_interval => 10, max_repetitions => 10, ignore_threshold => 1, ignore_duration => 500 }]);

$r = $d->request([RT_INFO,2252]);
is($r->[2]{global}{destination_ignores}, 0, "ignored destinations 0");
is($r->[2]{global}{oids_ignored}, 0, "ignored oids 0");
is($r->[2]{global}{max_packets_on_the_wire}, 1_000_000, "default global max packets");

$d->request([RT_SETOPT,42016,$target,$port,{global_max_packets=>100_000}]);

request_match($d, "times out", [RT_GET,41,$target,$port, ["1.3.6.1.2.1.1.5.0"]],
	[RT_GET|RT_REPLY,41,[["1.3.6.1.2.1.1.5.0",["timeout"]]]]);
for my $id (2241..2250) {
	request_match($d, "ignored $id", [RT_GET,$id,$target,$port, ["1.3.6.1.2.1.1.5.0"]],
		[RT_GET|RT_REPLY,$id,[["1.3.6.1.2.1.1.5.0",["ignored"]]]]);
}
$r = $d->request([RT_INFO,2251]);
is($r->[2]{global}{destination_ignores}, 1, "ignored destinations");
is($r->[2]{global}{oids_ignored}, 10, "ignored oids");
is($r->[2]{global}{max_packets_on_the_wire}, 100_000, "global max packets changed ok");

request_match($d, "change community to a good one", [RT_SETOPT,2253,$target,$port, {community=>"public"}],
	[RT_SETOPT|RT_REPLY,2253,
	{ip=>$target, port=>$port, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 100, retries => 2, min_interval => 10, max_repetitions => 10, ignore_threshold => 1, ignore_duration => 500}]);

Time::HiRes::sleep(0.7);

request_match($d, "past ignore interval", [RT_GET,2254,$target,$port, ["1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.25.1.1.0", "1.3.66"]],
	[RT_GET|RT_REPLY,2254,[
	["1.3.6.1.2.1.1.5.0",$hostname],
	["1.3.6.1.2.1.25.1.1.0",123456],
	["1.3.66",["no-such-object"]]]]);

$r = $d->request([RT_INFO,2255]);
is($r->[2]{global}{destination_ignores}, 1, "ignored destinations did not change");
is($r->[2]{global}{oids_ignored}, 10, "ignored oids did not change");

request_match($d, "switch off ignoring", [RT_SETOPT,3001,$target,$port, {ignore_threshold => 0}],
	[RT_SETOPT|RT_REPLY,3001,
	{ip=>$target, port=>$port, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 100, retries => 2, min_interval => 10, max_repetitions => 10, ignore_threshold => 0, ignore_duration => 500}]);

# 3. all is good / 3rd time lucky
request_match($d, "all is good", [RT_GET,42,$target,$port, ["1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.25.1.1.0", "1.3.66"]],
	[RT_GET|RT_REPLY,42,[
	["1.3.6.1.2.1.1.5.0",$hostname],
	["1.3.6.1.2.1.25.1.1.0",123456],
	["1.3.66",["no-such-object"]]]]);

request_match($d, "3rd time lucky", [RT_GET,110,$target,$port, ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.5.0"]],
	[RT_GET|RT_REPLY,110,[
	["1.3.6.1.2.1.1.5.0",$hostname],
	["1.3.6.1.2.1.1.5.0",$hostname],
	["1.3.6.1.2.1.1.5.0",$hostname],
	]]);

# 4. SNMP v1
request_match($d, "change version to SNMP v1", [RT_SETOPT,3002,$target,$port, {version=>1}],
	[RT_SETOPT|RT_REPLY,3002,
	{ip=>$target, port=>$port, community=>"public", version=>1, max_packets => 3, max_req_size => 1400, timeout => 100, retries => 2, min_interval => 10, max_repetitions => 10, }]);

request_match($d, "try request SNMP v1", [RT_GET,43,$target,$port, ["1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.25.1.1.0", "1.3.66"]],
	[RT_GET|RT_REPLY,43,[
	["1.3.6.1.2.1.1.5.0",["noSuchName"]],
	["1.3.6.1.2.1.25.1.1.0",["noSuchName"]],
	["1.3.66",["noSuchName"]]]]);

request_match($d, "ifDescr SNMPv1 table", [RT_GETTABLE,555,$target,$port,"1.3.6.1.2.1.2.2.1.2"], [RT_GETTABLE|RT_REPLY,555,T()]);

# 5. SNMP v2c table
request_match($d, "change version back to SNMP v2", [RT_SETOPT,3003,$target,$port, {version=>2}],
	[RT_SETOPT|RT_REPLY,3003,
	{ip=>$target, port=>$port, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 100, retries => 2, min_interval => 10, max_repetitions => 10, }]);

$r = request_match($d, "ifDescr SNMPv2c table",
	[RT_GETTABLE,3200,$target,$port,"1.3.6.1.2.1.2.2.1.2"],
	[RT_GETTABLE|RT_REPLY,3200,[
		["1.3.6.1.2.1.2.2.1.2.1","lo0"],
		["1.3.6.1.2.1.2.2.1.2.2","em0"],
		["1.3.6.1.2.1.2.2.1.2.3","em1"]]]);
my $first_ifindex = $r->[2][0][0];  $first_ifindex =~ s/.*\.(\d+)$/$1/;

my $rr = request_match($d, "ifDescr table small reps", [RT_GETTABLE,3201,$target,$port,"1.3.6.1.2.1.2.2.1.2",4], [RT_GETTABLE|RT_REPLY,3201,T()]);
is($rr->[2], $r->[2], "small reps same");
$rr = request_match($d, "ifDescr table large reps", [RT_GETTABLE,3202,$target,$port,"1.3.6.1.2.1.2.2.1.2",20], [RT_GETTABLE|RT_REPLY,3202,T()]);
is($rr->[2], $r->[2], "large reps same");

# 6. pipelining
$d->lone_request([RT_GET,3500,$target,$port, ["1.3.6.1.2.1.1.5.0"]]);
$d->lone_request([RT_GET,3501,$target,$port, [".1.3.6.1.2.1.25.1.1.0"]]);
Time::HiRes::sleep(0.5);
my ($r1,$r2) = $d->bulk_response();
if ($r1->[1] == 3501) {
	($r1, $r2) = ($r2, $r1);
}
is($r1, to_check([RT_GET|RT_REPLY,3500,[["1.3.6.1.2.1.1.5.0",$hostname]]]), "combined req1");
is($r2, to_check([RT_GET|RT_REPLY,3501,[["1.3.6.1.2.1.25.1.1.0",$uptime]]]), "combined req2");

$d->multi_request(
	[RT_GET,3502,$target,$port, ["1.3.6.1.2.1.1.5.0"]],
	[RT_GET,3503,$target,$port, [".1.3.6.1.2.1.25.1.1.0"]],
	[RT_GET,3504,$target,$port, ["1.3.6.1.2.1.2.1.0"]],
	[RT_GET,3505,$target,$port, ["1.3.6.1.2.1.2.2.1.1.$first_ifindex"]],
);
Time::HiRes::sleep(0.5);
my @multi = sort { $a->[1] <=> $b->[1] } $d->bulk_response();
is($multi[0], to_check([RT_GET|RT_REPLY,3502,[["1.3.6.1.2.1.1.5.0",$hostname]]]), "multi combined req1");
is($multi[1], to_check([RT_GET|RT_REPLY,3503,[["1.3.6.1.2.1.25.1.1.0",$uptime]]]), "multi combined req2");
is($multi[2], to_check([RT_GET|RT_REPLY,3504,[["1.3.6.1.2.1.2.1.0",$NUMBER]]]), "multi combined req3");
is($multi[3], to_check([RT_GET|RT_REPLY,3505,[["1.3.6.1.2.1.2.2.1.1.$first_ifindex",$first_ifindex]]]), "multi combined req4");

# 7. destinfo non-zero
request_match($d, "destinfo non-zero", [RT_DEST_INFO,6630,$target,$port], [RT_DEST_INFO|RT_REPLY, 6630,
	{ octets_received => qr/^[1-9]\d*$/, octets_sent => qr/^[1-9]\d*$/}]);

$agent->stop;
$d->stop;
done_testing;
