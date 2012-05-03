#! /usr/bin/perl
use 5.006;
use strict;
use warnings;
use IO::Socket::INET;
use Socket ':all';
use Time::HiRes 'sleep';
use Data::MessagePack;
use Data::Dump;

use constant RT_SETOPT   => 1;
use constant RT_INFO     => 3;
use constant RT_GET      => 4;
use constant RT_GETTABLE => 5;
use constant RT_REPLY    => 0x10;
use constant RT_ERROR    => 0x20;

our $mp = Data::MessagePack->new()->prefer_integer;
our $conn = IO::Socket::INET->new(PeerAddr => "127.0.0.1:7667", Proto => "tcp")
or die "cannot connect to snmp-query-engine daemon: $!\n";

my $target = shift || "127.0.0.1";

dd request([RT_SETOPT,3000,$target,161, {community=>"meow", timeout => 1500, retries => 2, version => 2}]);
dd request([RT_GET,41,$target,161, ["1.3.6.1.2.1.1.5.0"]]);
dd request([RT_INFO,3203]);

close $conn;

sub request
{
	my $d = shift;
	my $p = $mp->pack($d);
	$conn->syswrite($p);
	my $reply;
	$conn->sysread($reply, 65536);
	$mp->unpack($reply);
}

