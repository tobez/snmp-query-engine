#! /usr/bin/perl
use 5.006;
use strict;
use warnings;

use Data::MessagePack;
use IO::Socket::INET;

my $mp = Data::MessagePack->new()->prefer_integer;
my $conn = IO::Socket::INET->new(PeerAddr => "127.0.0.1:7667", Proto => "tcp");
$conn->print($mp->pack([0,42,{key=>"value"},["1.2.3","4.5.6"]]));
