#! /usr/bin/perl
use 5.006;
use strict;
use warnings;

use Data::MessagePack;
use IO::Socket::INET;
use Data::Dump;

our $mp = Data::MessagePack->new()->prefer_integer;
our $conn = IO::Socket::INET->new(PeerAddr => "127.0.0.1:7667", Proto => "tcp");

request({x=>1});  # not an array
request([]); # empty array
request([0]); # no id
request([0,-1]); # id is not a positive integer
request([0,"heps"]); # id is not a positive integer
request([-1,12]); # type is not a positive integer
request(["heps",13]); # type is not a positive integer
request([0,42,"127.0.0.1", 2, "public", ["1.3.6.1.2.1.1.5.0"]]);

sub request
{
	my $d = shift;
	$conn->print($mp->pack($d));
	my $reply;
	$conn->sysread($reply, 65536);
	dd $mp->unpack($reply);
}
