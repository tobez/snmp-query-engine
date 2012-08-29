#! /usr/bin/perl
use 5.006;
use strict;
use warnings;
use IO::Socket::INET;
use Socket ':all';
use Time::HiRes 'sleep';
use Net::SNMP::QueryEngine::AnyEvent;
use Data::Dump;

our $sqe = Net::SNMP::QueryEngine::AnyEvent->new;

if (@ARGV) {
	$sqe->cmd(sub { my ($h,$ok,$r) = @_; dd $r; },
		3, ++$sqe->{sqe}{cid}, 1);
} else {
	$sqe->info(sub { my ($h,$ok,$r) = @_; dd $r; });
}
$sqe->wait;
