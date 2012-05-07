#! /usr/bin/perl
use 5.006;
use strict;
use warnings;

use Data::MessagePack;
use IO::Socket::INET;
use Data::Dump qw(dd pp);
use Time::HiRes;
use FindBin;
use Socket ':all';
use Test::More;
use Sys::Hostname;

use constant RT_SETOPT   => 1;
use constant RT_GETOPT   => 2;
use constant RT_INFO     => 3;
use constant RT_GET      => 4;
use constant RT_GETTABLE => 5;
use constant RT_REPLY    => 0x10;
use constant RT_ERROR    => 0x20;

sub THERE () { return bless \my $dummy, 't::Present' }
our $NUMBER = qr/^\d+$/;

my $daemon_pid;
if (!($daemon_pid = fork)) {
	exec("$FindBin::Bin/../snmp-query-engine", "-p7668", "-q");
	exit;  # unreach
}

Time::HiRes::sleep(0.2);
our $mp = Data::MessagePack->new()->prefer_integer;
our $conn = IO::Socket::INET->new(PeerAddr => "127.0.0.1:7668", Proto => "tcp")
	or die "cannot connect to snmp-query-engine daemon: $!\n";

request_match("defaults via getopt", [RT_GETOPT,2000,"127.0.0.1",161], [RT_GETOPT|RT_REPLY,2000,
	{ip=>"127.0.0.1", port=>161, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 2000, retries => 3, min_interval => 10, request_delay => 20}]);
request_match("defaults via setopt", [RT_SETOPT,2001,"127.0.0.1",161, {}], [RT_SETOPT|RT_REPLY,2001,
	{ip=>"127.0.0.1", port=>161, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 2000, retries => 3, min_interval => 10, request_delay => 20}]);
request_match("setopt bad length", [RT_SETOPT,2002,"127.0.0.1",161], [RT_SETOPT|RT_ERROR,2002,qr/bad request length/]);
request_match("setopt bad port 1", [RT_SETOPT,2003,"127.0.0.1","x",{}], [RT_SETOPT|RT_ERROR,2003,qr/bad port number/]);
request_match("setopt bad port 2", [RT_SETOPT,2004,"127.0.0.1",80000,{}], [RT_SETOPT|RT_ERROR,2004,qr/bad port number/]);
request_match("setopt bad IP", [RT_SETOPT,2005,"127.260.0.1",161,{}], [RT_SETOPT|RT_ERROR,2005,qr/bad IP/]);
request_match("setopt opt not map 1", [RT_SETOPT,2006,"127.0.0.1",161,[]], [RT_SETOPT|RT_ERROR,2006,qr/not a map/]);
request_match("setopt opt not map 2", [RT_SETOPT,2007,"127.0.0.1",161,42], [RT_SETOPT|RT_ERROR,2007,qr/not a map/]);
request_match("setopt bad option key", [RT_SETOPT,2008,"127.0.0.1",161,{meow=>1}], [RT_SETOPT|RT_ERROR,2008,qr/bad option key/]);
request_match("setopt bad version 1", [RT_SETOPT,2009,"127.0.0.1",161,{version=>42}], [RT_SETOPT|RT_ERROR,2009,qr/invalid SNMP version/]);
request_match("setopt bad version 2", [RT_SETOPT,2010,"127.0.0.1",161,{version=>"x"}], [RT_SETOPT|RT_ERROR,2010,qr/invalid SNMP version/]);
request_match("setopt bad community", [RT_SETOPT,2011,"127.0.0.1",161,{community=>[]}], [RT_SETOPT|RT_ERROR,2011,qr/invalid SNMP community/]);
request_match("setopt bad max_packets 1", [RT_SETOPT,2012,"127.0.0.1",161,{max_packets=>"meow"}], [RT_SETOPT|RT_ERROR,2012,qr/invalid max packets/]);
request_match("setopt bad max_packets 2", [RT_SETOPT,2013,"127.0.0.1",161,{max_packets=>0}], [RT_SETOPT|RT_ERROR,2013,qr/invalid max packets/]);
request_match("setopt bad max_packets 3", [RT_SETOPT,2014,"127.0.0.1",161,{max_packets=>30000}], [RT_SETOPT|RT_ERROR,2014,qr/invalid max packets/]);
request_match("setopt bad max req size 1", [RT_SETOPT,2015,"127.0.0.1",161,{max_req_size=>"foo"}], [RT_SETOPT|RT_ERROR,2015,qr/invalid max request size/]);
request_match("setopt bad max req size 2", [RT_SETOPT,2016,"127.0.0.1",161,{max_req_size=>480}], [RT_SETOPT|RT_ERROR,2016,qr/invalid max request size/]);
request_match("setopt bad max req size 3", [RT_SETOPT,2017,"127.0.0.1",161,{max_req_size=>52000}], [RT_SETOPT|RT_ERROR,2017,qr/invalid max request size/]);
request_match("setopt bad timeout 1", [RT_SETOPT,2018,"127.0.0.1",161,{timeout=>"st"}], [RT_SETOPT|RT_ERROR,2018,qr/invalid timeout/]);
request_match("setopt bad timeout 2", [RT_SETOPT,2019,"127.0.0.1",161,{timeout=>31000}], [RT_SETOPT|RT_ERROR,2019,qr/invalid timeout/]);
request_match("setopt bad retries 1", [RT_SETOPT,2020,"127.0.0.1",161,{retries=>"foo"}], [RT_SETOPT|RT_ERROR,2020,qr/invalid retries/]);
request_match("setopt bad retries 2", [RT_SETOPT,2021,"127.0.0.1",161,{retries=>0}], [RT_SETOPT|RT_ERROR,2021,qr/invalid retries/]);
request_match("setopt bad retries 3", [RT_SETOPT,2022,"127.0.0.1",161,{retries=>12}], [RT_SETOPT|RT_ERROR,2022,qr/invalid retries/]);
request_match("setopt bad min interval 1", [RT_SETOPT,2120,"127.0.0.1",161,{min_interval=>"foo"}], [RT_SETOPT|RT_ERROR,2120,qr/invalid min interval/]);
request_match("setopt bad min interval 2", [RT_SETOPT,2122,"127.0.0.1",161,{min_interval=>10002}], [RT_SETOPT|RT_ERROR,2122,qr/invalid min interval/]);
request_match("setopt bad request delay 1", [RT_SETOPT,2220,"127.0.0.1",161,{request_delay=>"foo"}], [RT_SETOPT|RT_ERROR,2220,qr/invalid request delay/]);
request_match("setopt bad request delay 2", [RT_SETOPT,2222,"127.0.0.1",161,{request_delay=>3005}], [RT_SETOPT|RT_ERROR,2222,qr/invalid request delay/]);
request_match("defaults unchanged", [RT_SETOPT,2023,"127.0.0.1",161, {}], [RT_SETOPT|RT_REPLY,2023,
	{ip=>"127.0.0.1", port=>161, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 2000, retries => 3, min_interval => 10, request_delay => 20}]);
request_match("change timeout", [RT_SETOPT,2024,"127.0.0.1",161, {timeout=>1500}], [RT_SETOPT|RT_REPLY,2024,
	{ip=>"127.0.0.1", port=>161, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 1500, retries => 3, min_interval => 10, request_delay => 20}]);
request_match("correct timeout via getopt", [RT_GETOPT,2025,"127.0.0.1",161], [RT_GETOPT|RT_REPLY,2025,
	{ip=>"127.0.0.1", port=>161, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 1500, retries => 3, min_interval => 10, request_delay => 20}]);

request_match("bad request: not an array 1", {x=>1}, [RT_ERROR,0,qr/not an array/]);
request_match("bad request: not an array 2", 55, [RT_ERROR,0,qr/not an array/]);
request_match("bad request: not an array 3", "hello", [RT_ERROR,0,qr/not an array/]);
request_match("bad request: empty array", [], [RT_ERROR,0,qr/empty array/]);
request_match("bad request: no id", [RT_GET], [RT_ERROR,0,qr/without an id/]);
request_match("bad request: bad id 1", [RT_GET,-1], [RT_ERROR,0,qr/id is not a positive integer/]);
request_match("bad request: bad id 2", [RT_GET,"heps"], [RT_ERROR,0,qr/id is not a positive integer/]);
request_match("bad request: bad type 1", [-1,12], [RT_ERROR,12,qr/type is not a positive integer/]);
request_match("bad request: bad type 2", ["heps",13], [RT_ERROR,13,qr/type is not a positive integer/]);
request_match("bad request: unknown type", [9,14], [RT_ERROR|9,14,qr/unknown request type/i]);
request_match("bad request length 1", [RT_GET,15,"127.0.0.1",161, 2, "public"], [RT_GET|RT_ERROR,15,qr/bad request length/i]);
request_match("bad request length 2", [RT_GET,16,"127.0.0.1",161, 2, "public", ["1.3.6.1.2.1.1.5.0"], "heh", "heh"],
			  [RT_GET|RT_ERROR,16,qr/bad request length/i]);
request_match("bad port number #1", [RT_GET,17,"127.0.0.1",-2, ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,17,qr/bad port number/i]);
request_match("bad port number #2", [RT_GET,18,"127.0.0.1",[], ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,18,qr/bad port number/i]);
request_match("bad port number #3", [RT_GET,19,"127.0.0.1",66666, ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,19,qr/bad port number/i]);
request_match("bad IP 1", [RT_GET,21,666,161, ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,21,qr/bad IP/i]);
request_match("bad IP 2", [RT_GET,22,[],161, ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,22,qr/bad IP/i]);
request_match("bad IP 3", [RT_GET,23,"257.12.22.13",161, ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,23,qr/bad IP/i]);
request_match("oids is not an array 1", [RT_GET,24,"127.0.0.1",161, 42], [RT_GET|RT_ERROR,24,qr/oids must be an array/i]);
request_match("oids is not an array 2", [RT_GET,25,"127.0.0.1",161, {}], [RT_GET|RT_ERROR,25,qr/oids must be an array/i]);
request_match("oids is not an array 3", [RT_GET,26,"127.0.0.1",161, "oids"], [RT_GET|RT_ERROR,26,qr/oids must be an array/i]);
request_match("oids is an empty array", [RT_GET,27,"127.0.0.1",161, []], [RT_GET|RT_ERROR,27,qr/oids is an empty array/i]);

my $target   = "127.0.0.1";
my $hostname = hostname;
my $uptime   = qr/^\d+$/;
if ($^O eq "linux" && !-f "/etc/redhat-release") {
	$target   = "172.24.253.189";
	$hostname = qr/ryv/;
	$uptime   = ["no-such-object"];
}

request_match("change community to a bad one", [RT_SETOPT,3000,$target,161, {community=>"meow", timeout => 1500, retries => 2}], [RT_SETOPT|RT_REPLY,3000,
	{ip=>$target, port=>161, community=>"meow", version=>2, max_packets => 3, max_req_size => 1400, timeout => 1500, retries => 2, min_interval => 10, request_delay => 20}]);

my $r;
$r = request_match("times out", [RT_GET,41,$target,161, ["1.3.6.1.2.1.1.5.0"]],
			  [RT_GET|RT_REPLY,41,[["1.3.6.1.2.1.1.5.0",["timeout"]]]]);

request_match("change community to a good one", [RT_SETOPT,3001,$target,161, {community=>"public"}], [RT_SETOPT|RT_REPLY,3001,
	{ip=>$target, port=>161, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 1500, retries => 2, min_interval => 10, request_delay => 20}]);

request_match("all is good", [RT_GET,42,$target,161, ["1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.25.1.1.0", "1.3.66"]],
			  [RT_GET|RT_REPLY,42,[
			  ["1.3.6.1.2.1.1.5.0",$hostname],
			  ["1.3.6.1.2.1.25.1.1.0",$uptime],
			  ["1.3.66",["no-such-object"]]]]);

request_match("3rd time lucky", [RT_GET,110,$target,161, ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.5.0"]],
			  [RT_GET|RT_REPLY,110,[
			  ["1.3.6.1.2.1.1.5.0",$hostname],
			  ["1.3.6.1.2.1.1.5.0",$hostname],
			  ["1.3.6.1.2.1.1.5.0",$hostname],
			  ]]);

request_match("change version to SNMP v1", [RT_SETOPT,3002,$target,161, {version=>1}], [RT_SETOPT|RT_REPLY,3002,
	{ip=>$target, port=>161, community=>"public", version=>1, max_packets => 3, max_req_size => 1400, timeout => 1500, retries => 2, min_interval => 10, request_delay => 20}]);

request_match("try request SNMP v1", [RT_GET,43,$target,161, ["1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.25.1.1.0", "1.3.66"]],
			  [RT_GET|RT_REPLY,43,[
			  ["1.3.6.1.2.1.1.5.0",undef],
			  ["1.3.6.1.2.1.25.1.1.0",undef],
			  ["1.3.66",undef]]]);

request_match("change version back to SNMP v2", [RT_SETOPT,3003,$target,161, {version=>2}], [RT_SETOPT|RT_REPLY,3003,
	{ip=>$target, port=>161, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 1500, retries => 2, min_interval => 10, request_delay => 20}]);

$r = request_match("ifDescr table", [RT_GETTABLE,3200,$target,161,"1.3.6.1.2.1.2.2.1.2"], [RT_GETTABLE|RT_REPLY,3200,THERE]);
print STDERR pp $r;

$r = request_match("stats", [RT_INFO,5000], [RT_INFO|RT_REPLY,5000,
	{ connection => { client_requests => $NUMBER, invalid_requests => $NUMBER },
	  global => { client_requests => $NUMBER, invalid_requests => $NUMBER,
	  	active_client_connections => 1, total_client_connections => 1 }}]);
print STDERR "OIDS requested: $r->[2]{connection}{oids_requested}\n";

Time::HiRes::sleep(0.2);
close $conn;
Time::HiRes::sleep(0.2);
kill 15, $daemon_pid;

done_testing;

sub request_match
{
	my ($t, $req, $mat) = @_;
	my $res = request($req);
	match($t, $res, $mat);
	return $res;
}

sub request
{
	my $d = shift;
	my $p = $mp->pack($d);
	$conn->syswrite($p);
	my $reply;
	$conn->sysread($reply, 65536);
	$mp->unpack($reply);
}

sub match
{
	my ($t, $result, $template) = @_;
	if (!ref $result && !ref $template) {
		is($result, $template, "$t: matches");
		return;
	}
	if (ref $template && ref $template eq "Regexp") {
		like($result, $template, "$t: matches");
		return;
	}
	if (ref $template && ref $template eq "Test::Deep::Regexp") {
		like($result, $template->{val}, "$t: matches");
		return;
	}
	if (ref $template && ref $template eq "t::Present") {
		# ok if we got that far
		return;
	}
	unless (ref $result && ref $template) {
		fail("$t: apples to oranges");
		return;
	}
	my $tt = $t;
	$tt .= ": " unless $tt =~ /[\]}]$/;
	if (is(ref($result), ref($template), "$t: same reftype")) {
		if (UNIVERSAL::isa($result, "HASH")) {
			for my $k (keys %$template) {
				if (ok(exists $result->{$k}, "$t: \"$k\" exists")) {
					match("$tt\{$k}", $result->{$k}, $template->{$k});
				}
			}
		} elsif (UNIVERSAL::isa($result, "ARRAY")) {
			if (ok(@$result == @$template, "$t: array size matches")) {
				for my $i (0..$#$result) {
					match("$tt\[$i]", $result->[$i], $template->[$i]);
				}
			}
		}
	}
}
