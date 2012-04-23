#! /usr/bin/perl
use 5.006;
use strict;
use warnings;
use IO::Socket::INET;
use Socket ':all';
use Time::HiRes 'sleep';

our $conn = IO::Socket::INET->new(PeerAddr => "127.0.0.1:7667", Proto => "tcp")
or die "cannot connect to snmp-query-engine daemon: $!\n";
$conn->syswrite("          " x 1000);
sleep 0.2;
close $conn;
