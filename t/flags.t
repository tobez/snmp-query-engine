#!/usr/bin/env perl
# ABOUTME: Command-line flag tests: -b bind address acceptance and
# ABOUTME: rejection of garbage arguments with a usage error.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;
use SQE::Test qw(spawn_daemon RT_INFO RT_REPLY);

my $engine = "$FindBin::Bin/../snmp-query-engine";

subtest 'explicit -b 127.0.0.1 works' => sub {
	my $d = spawn_daemon(args => ['-q', '-b', '127.0.0.1']);
	my $res = $d->request([RT_INFO, 1]);
	is($res->[0], RT_INFO|RT_REPLY, 'daemon answers with explicit bind address');
};

subtest 'garbage -b is rejected' => sub {
	my $out = qx($engine -b not-an-address -p 65098 2>&1);
	isnt($? >> 8, 0, 'daemon exits nonzero');
	like($out, qr/bind address/, 'usage error mentions bind address');
};

done_testing;
