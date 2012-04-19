#! /usr/bin/perl
use 5.006;
use strict;
use warnings;

use Data::MessagePack;
use IO::Socket::INET;
use Data::Dump;
use Time::HiRes;
use FindBin;
use Socket ':all';
use Test::More;

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

request_match("bad request: not an array 1", {x=>1}, [30,0,qr/not an array/]);
request_match("bad request: not an array 2", 55, [30,0,qr/not an array/]);
request_match("bad request: not an array 3", "hello", [30,0,qr/not an array/]);
request_match("bad request: empty array", [], [30,0,qr/empty array/]);
request_match("bad request: no id", [0], [30,0,qr/without an id/]);
request_match("bad request: bad id 1", [0,-1], [30,0,qr/id is not a positive integer/]);
request_match("bad request: bad id 2", [0,"heps"], [30,0,qr/id is not a positive integer/]);
request_match("bad request: bad type 1", [-1,12], [30,12,qr/type is not a positive integer/]);
request_match("bad request: bad type 2", ["heps",13], [30,13,qr/type is not a positive integer/]);
request_match("bad request: unknown type", [9,14], [29,14,qr/unknown request type/i]);
request_match("bad request length 1", [0,15,"127.0.0.1",161, 2], [20,15,qr/bad request length/i]);
request_match("bad request length 2", [0,16,"127.0.0.1",161, 2, "public", ["1.3.6.1.2.1.1.5.0"], "heh", "heh"],
			  [20,16,qr/bad request length/i]);
request_match("bad SNMP version #1", [0,17,"127.0.0.1",161, 0, "public", ["1.3.6.1.2.1.1.5.0"]], [20,17,qr/bad SNMP version/i]);
request_match("bad SNMP version #2", [0,18,"127.0.0.1",161, 3, "public", ["1.3.6.1.2.1.1.5.0"]], [20,18,qr/bad SNMP version/i]);
request_match("bad SNMP version #3", [0,19,"127.0.0.1",161, "meow", "public", ["1.3.6.1.2.1.1.5.0"]], [20,19,qr/bad SNMP version/i]);
request_match("bad port number #1", [0,17,"127.0.0.1",-2, 1, "public", ["1.3.6.1.2.1.1.5.0"]], [20,17,qr/bad port number/i]);
request_match("bad port number #2", [0,18,"127.0.0.1",[], 1, "public", ["1.3.6.1.2.1.1.5.0"]], [20,18,qr/bad port number/i]);
request_match("bad port number #3", [0,19,"127.0.0.1",66666, 1, "public", ["1.3.6.1.2.1.1.5.0"]], [20,19,qr/bad port number/i]);
request_match("bad community", [0,20,"127.0.0.1",161, 1, [], ["1.3.6.1.2.1.1.5.0"]], [20,20,qr/bad community/i]);
request_match("bad IP 1", [0,21,666,161, 1, "public", ["1.3.6.1.2.1.1.5.0"]], [20,21,qr/bad IP/i]);
request_match("bad IP 2", [0,22,[],161, 1, "public", ["1.3.6.1.2.1.1.5.0"]], [20,22,qr/bad IP/i]);
request_match("bad IP 3", [0,23,"257.12.22.13",161, 1, "public", ["1.3.6.1.2.1.1.5.0"]], [20,23,qr/bad IP/i]);
request_match("oids is not an array 1", [0,24,"127.0.0.1",161, 2, "meow", 42], [20,24,qr/oids must be an array/i]);
request_match("oids is not an array 2", [0,25,"127.0.0.1",161, 2, "meow", {}], [20,25,qr/oids must be an array/i]);
request_match("oids is not an array 3", [0,26,"127.0.0.1",161, 2, "meow", "oids"], [20,26,qr/oids must be an array/i]);
request_match("oids is an empty array", [0,27,"127.0.0.1",161, 2, "meow", []], [20,27,qr/oids is an empty array/i]);

my $target = $^O eq "linux" ? "172.24.253.189" : "127.0.0.1";

request_match("fails for now", [0,41,$target,161, 2, "meow", ["1.3.6.1.2.1.1.5.0"]],
			  [20,41,qr/not implemented/i]);
#sleep 7;
request_match("fails for now", [0,42,$target,161, 2, "public", ["1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.25.1.1.0", "1.3.66"]],
			  [20,42,qr/not implemented/i]);

close $conn;
Time::HiRes::sleep(0.2);
kill 15, $daemon_pid;

done_testing;

sub request_match
{
	my ($t, $req, $mat) = @_;
	match($t, request($req), $mat);
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
