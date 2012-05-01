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

use constant RT_GETOPT => 2;
use constant RT_GET => 4;
use constant RT_REPLY => 0x10;
use constant RT_ERROR => 0x20;

sub THERE () { return bless \my $dummy, 't::Present' }

my $daemon_pid;
if (!($daemon_pid = fork)) {
	exec("$FindBin::Bin/../snmp-query-engine", "-p7668", "-q");
	exit;  # unreach
}

Time::HiRes::sleep(0.2);
our $mp = Data::MessagePack->new()->prefer_integer;
our $conn = IO::Socket::INET->new(PeerAddr => "127.0.0.1:7668", Proto => "tcp")
	or die "cannot connect to snmp-query-engine daemon: $!\n";

request_match("defaults", [RT_GETOPT,2000,"127.0.0.1",161], [RT_GETOPT|RT_REPLY,2000,
	{ip=>"127.0.0.1", port=>161, community=>"public", version=>2, max_packets => 3, max_req_size => 1400, timeout => 2000, retries => 3}]);
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
request_match("bad request length 1", [RT_GET,15,"127.0.0.1",161, 2], [RT_GET|RT_ERROR,15,qr/bad request length/i]);
request_match("bad request length 2", [RT_GET,16,"127.0.0.1",161, 2, "public", ["1.3.6.1.2.1.1.5.0"], "heh", "heh"],
			  [RT_GET|RT_ERROR,16,qr/bad request length/i]);
request_match("bad SNMP version #1", [RT_GET,17,"127.0.0.1",161, 0, "public", ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,17,qr/bad SNMP version/i]);
request_match("bad SNMP version #2", [RT_GET,18,"127.0.0.1",161, 3, "public", ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,18,qr/bad SNMP version/i]);
request_match("bad SNMP version #3", [RT_GET,19,"127.0.0.1",161, "meow", "public", ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,19,qr/bad SNMP version/i]);
request_match("bad port number #1", [RT_GET,17,"127.0.0.1",-2, 1, "public", ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,17,qr/bad port number/i]);
request_match("bad port number #2", [RT_GET,18,"127.0.0.1",[], 1, "public", ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,18,qr/bad port number/i]);
request_match("bad port number #3", [RT_GET,19,"127.0.0.1",66666, 1, "public", ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,19,qr/bad port number/i]);
request_match("bad community", [RT_GET,20,"127.0.0.1",161, 1, [], ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,20,qr/bad community/i]);
request_match("bad IP 1", [RT_GET,21,666,161, 1, "public", ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,21,qr/bad IP/i]);
request_match("bad IP 2", [RT_GET,22,[],161, 1, "public", ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,22,qr/bad IP/i]);
request_match("bad IP 3", [RT_GET,23,"257.12.22.13",161, 1, "public", ["1.3.6.1.2.1.1.5.0"]], [RT_GET|RT_ERROR,23,qr/bad IP/i]);
request_match("oids is not an array 1", [RT_GET,24,"127.0.0.1",161, 2, "meow", 42], [RT_GET|RT_ERROR,24,qr/oids must be an array/i]);
request_match("oids is not an array 2", [RT_GET,25,"127.0.0.1",161, 2, "meow", {}], [RT_GET|RT_ERROR,25,qr/oids must be an array/i]);
request_match("oids is not an array 3", [RT_GET,26,"127.0.0.1",161, 2, "meow", "oids"], [RT_GET|RT_ERROR,26,qr/oids must be an array/i]);
request_match("oids is an empty array", [RT_GET,27,"127.0.0.1",161, 2, "meow", []], [RT_GET|RT_ERROR,27,qr/oids is an empty array/i]);

my $target   = "127.0.0.1";
my $hostname = hostname;
my $uptime   = qr/^\d+$/;
if ($^O eq "linux") {
	$target   = "172.24.253.189";
	$hostname = qr/ryv/;
	$uptime   = ["no-such-object"];
}

my $r;
$r = request_match("fails for now", [RT_GET,41,$target,161, 2, "meow", ["1.3.6.1.2.1.1.5.0"]],
			  [RT_GET|RT_REPLY,41,[["1.3.6.1.2.1.1.5.0",["timeout"]]]]);
print STDERR pp $r;
#sleep 7;
$r = request_match("fails for now", [RT_GET,42,$target,161, 2, "public", ["1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.25.1.1.0", "1.3.66"]],
			  [RT_GET|RT_REPLY,42,[
			  ["1.3.6.1.2.1.1.5.0",$hostname],
			  ["1.3.6.1.2.1.25.1.1.0",$uptime],
			  ["1.3.66",["no-such-object"]]]]);
print STDERR pp $r;

# version 1
$r = request_match("fails for now", [RT_GET,43,$target,161, 1, "public", ["1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.25.1.1.0", "1.3.66"]],
			  [RT_GET|RT_REPLY,43,[
			  ["1.3.6.1.2.1.1.5.0",undef],
			  ["1.3.6.1.2.1.25.1.1.0",undef],
			  ["1.3.66",undef]]]);
print STDERR pp $r;

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
	if (ref $template && ref $template eq "t::Tools::Present") {
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
