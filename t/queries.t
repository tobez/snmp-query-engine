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

request_match("fails for now", [0,42,"127.0.0.1", 2, "public", ["1.3.6.1.2.1.1.5.0"]],
			  [20,42,qr/not implemented/i]);

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
