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

# --- end-to-end non-increasing-OID walk termination (dk's PR #8 fix) ---
{
	my $stuck = SQE::FakeAgent->spawn(tree => \@tree,
		repeat_oid => '1.3.6.1.2.1.2.2.1.2.2');
	my $sport = $stuck->port;
	my $before = $d->request([RT_INFO, 7000]);
	# Observed against the real engine: rows collected before the repeat ARE
	# included in the reply, followed by one synthetic entry for the repeated
	# oid carrying the ["non-increasing"] error marker (sid_info.c
	# process_sid_info_response calls got_table_oid() for every row up to and
	# including the non-increasing one before it stops the walk).
	my $r = request_match($d, "walk of a non-increasing device terminates",
		[RT_GETTABLE, 7001, $target, $sport, "1.3.6.1.2.1.2.2.1.2"],
		[RT_GETTABLE|RT_REPLY, 7001, [
			["1.3.6.1.2.1.2.2.1.2.1", "lo0"],
			["1.3.6.1.2.1.2.2.1.2.2", "em0"],
			["1.3.6.1.2.1.2.2.1.2.2", ["non-increasing"]],
		]]);
	my $after = $d->request([RT_INFO, 7002]);
	ok($after->[2]{global}{oids_non_increasing} > ($before->[2]{global}{oids_non_increasing} // 0),
		"oids_non_increasing counter incremented");
	is(ref $r->[2], 'ARRAY', "walk returned a table, not a hang");
	$stuck->stop;
}

# --- malformed replies bump bad_snmp_responses; request eventually times out ---
{
	my $garbler = SQE::FakeAgent->spawn(tree => \@tree, malformed => 'garbage');
	my $gport = $garbler->port;
	request_match($d, "fast timeout for the garbler",
		[RT_SETOPT, 7100, $target, $gport, {timeout => 100, retries => 1}],
		[RT_SETOPT|RT_REPLY, 7100, T()]);
	my $before = $d->request([RT_INFO, 7101]);
	request_match($d, "garbage reply leads to timeout",
		[RT_GET, 7102, $target, $gport, ["1.3.6.1.2.1.1.5.0"]],
		[RT_GET|RT_REPLY, 7102, [["1.3.6.1.2.1.1.5.0", ["timeout"]]]]);
	my $after = $d->request([RT_INFO, 7103]);
	# Observed against the real engine: bad_snmp_responses increments once per
	# received malformed reply, not once per request. With retries => 1 there is
	# exactly one SNMP round-trip, so the delta is deterministically exactly 1
	# (confirmed separately: retries => 3 against the same garbler yields a
	# delta of 3, one per attempt).
	is($after->[2]{global}{bad_snmp_responses}, ($before->[2]{global}{bad_snmp_responses} // 0) + 1,
		"bad_snmp_responses incremented by exactly one");
	$garbler->stop;
}

# --- drop_first makes retry behavior deterministic ---
{
	my $droppy = SQE::FakeAgent->spawn(tree => \@tree, drop_first => 2);
	my $dport = $droppy->port;
	request_match($d, "fast timeout for the dropper",
		[RT_SETOPT, 7200, $target, $dport, {timeout => 100, retries => 3}],
		[RT_SETOPT|RT_REPLY, 7200, T()]);
	my $before = $d->request([RT_INFO, 7201]);
	request_match($d, "get succeeds on the third attempt",
		[RT_GET, 7202, $target, $dport, ["1.3.6.1.2.1.1.5.0"]],
		[RT_GET|RT_REPLY, 7202, [["1.3.6.1.2.1.1.5.0", $hostname]]]);
	my $after = $d->request([RT_INFO, 7203]);
	# Observed against the real engine: with drop_first => 2 and retries => 3,
	# the first two sends are dropped and the third succeeds, so exactly two
	# resends (retries) happen; the delta is deterministically exactly 2.
	is($after->[2]{global}{snmp_retries} - $before->[2]{global}{snmp_retries}, 2,
		"exactly two retries recorded");
	$droppy->stop;
}

# --- negative INTEGER values ---
# _enc_int byte-level pins: minimal two's-complement encodings
is(SQE::FakeAgent::_enc_int(0x02, 0),          "\x02\x01\x00",             "_enc_int 0");
is(SQE::FakeAgent::_enc_int(0x02, 127),        "\x02\x01\x7f",             "_enc_int 127");
is(SQE::FakeAgent::_enc_int(0x02, 128),        "\x02\x02\x00\x80",         "_enc_int 128");
is(SQE::FakeAgent::_enc_int(0x02, -1),         "\x02\x01\xff",             "_enc_int -1");
is(SQE::FakeAgent::_enc_int(0x02, -5),         "\x02\x01\xfb",             "_enc_int -5");
is(SQE::FakeAgent::_enc_int(0x02, -128),       "\x02\x01\x80",             "_enc_int -128");
is(SQE::FakeAgent::_enc_int(0x02, -129),       "\x02\x02\xff\x7f",         "_enc_int -129");
is(SQE::FakeAgent::_enc_int(0x02, -32768),     "\x02\x02\x80\x00",         "_enc_int -32768");
is(SQE::FakeAgent::_enc_int(0x02, 2147483647), "\x02\x04\x7f\xff\xff\xff", "_enc_int INT32_MAX");

{
	my $neg = SQE::FakeAgent->spawn(tree => [
		['1.3.6.1.2.1.99.1', int => -5],
		['1.3.6.1.2.1.99.2', int => -129],
		['1.3.6.1.2.1.99.3', int => -32768],
		['1.3.6.1.2.1.99.4', int => -2147483648],
		['1.3.6.1.2.1.99.5', int => 2147483647],
	]);
	my $nport = $neg->port;
	request_match($d, "negative INTEGER values decode correctly",
		[RT_GET, 7300, $target, $nport, ["1.3.6.1.2.1.99.1", "1.3.6.1.2.1.99.2", "1.3.6.1.2.1.99.3", "1.3.6.1.2.1.99.4", "1.3.6.1.2.1.99.5"]],
		[RT_GET|RT_REPLY, 7300, [
			["1.3.6.1.2.1.99.1", -5],
			["1.3.6.1.2.1.99.2", -129],
			["1.3.6.1.2.1.99.3", -32768],
			["1.3.6.1.2.1.99.4", -2147483648],
			["1.3.6.1.2.1.99.5", 2147483647],
		]]);
	$neg->stop;
}

$agent->stop;
$d->stop;
done_testing;
