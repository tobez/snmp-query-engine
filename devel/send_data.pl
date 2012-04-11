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

my $daemon_pid;
if (!($daemon_pid = fork)) {
	exec("$FindBin::Bin/../snmp-query-engine", "-p7668");
	exit;  # unreach
}

Time::HiRes::sleep(0.5);
our $mp = Data::MessagePack->new()->prefer_integer;
our $conn = IO::Socket::INET->new(PeerAddr => "127.0.0.1:7668", Proto => "tcp");
my $xx = getsockopt($conn, SOL_SOCKET, SO_SNDLOWAT);
my $lowat = unpack("I", $xx);
print "SNDLOWAT is $lowat\n";
$xx = getsockopt($conn, SOL_SOCKET, SO_RCVLOWAT);
$lowat = unpack("I", $xx);
print "RCVLOWAT is $lowat\n";
my $tcp = IPPROTO_TCP;
my $packed = getsockopt($conn, $tcp, TCP_NODELAY)
	or die "getsockopt TCP_NODELAY: $!";
my $nodelay = unpack("I", $packed);
print "Nagle's algorithm is turned ", $nodelay ? "off\n" : "on\n";

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
	print "packing "; dd $d;
	my $p = $mp->pack($d);
	print "sending ", length($p), " bytes\n";
	$conn->syswrite($p);
	my $reply;
	print "reading\n";
	$conn->sysread($reply, 65536);
	dd $mp->unpack($reply);
}
