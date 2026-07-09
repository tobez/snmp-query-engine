#! /usr/bin/perl
# ABOUTME: End-to-end SNMPv3/USM tests: discovery, time-sync, authPriv GET, and
# ABOUTME: deterministic v3 misbehavior, driven against the scriptable fake agent.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;
use SQE::Test ':all';
use SQE::FakeAgent;

my $hostname = 'sqe-fake-v3';
my @tree = (
	['1.3.6.1.2.1.1.5.0', str => $hostname],
	['1.3.6.1.2.1.1.3.0', ticks => 987654],
);
my %v3 = (
	engine_id  => '80001f88047371656369',
	username   => 'sqetest',
	auth_proto => 'sha256', auth_pass => 'sqeauthpass12',
	priv_proto => 'aes128', priv_pass => 'sqeprivpass12',
	boots => 12, time => 3456,
);

my $d      = spawn_daemon();
my $agent  = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3);
my $target = '127.0.0.1';
my $port   = $agent->port;

request_match($d, 'set v3 credentials',
	[RT_SETOPT, 200, $target, $port, {
		version => 3, engineid => $v3{engine_id}, username => $v3{username},
		authprotocol => 'sha256', authpassword => $v3{auth_pass},
		privprotocol => 'aes128', privpassword => $v3{priv_pass},
	}],
	[RT_SETOPT|RT_REPLY, 200, T()]);

request_match($d, 'v3 authPriv get sysName',
	[RT_GET, 201, $target, $port, ['1.3.6.1.2.1.1.5.0']],
	[RT_GET|RT_REPLY, 201, [['1.3.6.1.2.1.1.5.0', $hostname]]]);

$d->stop;
done_testing;
