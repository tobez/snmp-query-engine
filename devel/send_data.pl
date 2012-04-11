#! /usr/bin/perl
use 5.006;
use strict;
use warnings;

use Data::MessagePack;
use IO::Socket::INET;
use Data::Dump;
use Time::HiRes;
use FindBin;

my $daemon_pid;
if (!($daemon_pid = fork)) {
	exec("$FindBin::Bin/../snmp-query-engine", "-p7668", "-q");
	exit;  # unreach
}

Time::HiRes::sleep(0.2);
our $mp = Data::MessagePack->new()->prefer_integer;
our $conn = IO::Socket::INET->new(PeerAddr => "127.0.0.1:7668", Proto => "tcp");

request({x=>1});  # not an array
request([]); # empty array
request([0]); # no id
request([0,-1]); # id is not a positive integer
request([0,"heps"]); # id is not a positive integer
request([-1,12]); # type is not a positive integer
request(["heps",13]); # type is not a positive integer
request([1,14]); # unknown request type
request([0,42,"127.0.0.1", 2, "public", ["1.3.6.1.2.1.1.5.0"]]);

kill 15, $daemon_pid;

sub request
{
	my $d = shift;
	$conn->print($mp->pack($d));
	my $reply;
	$conn->sysread($reply, 65536);
	dd $mp->unpack($reply);
}
