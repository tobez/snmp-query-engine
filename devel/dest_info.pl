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

$sqe->dest_info(sub { my ($h,$ok,$r) = @_; dd $r; }, "127.0.0.1", 161);
$sqe->wait;
