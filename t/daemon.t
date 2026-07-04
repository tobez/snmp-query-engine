#!/usr/bin/env perl
# ABOUTME: Daemon lifecycle tests: graceful SIGTERM/SIGINT exit, SIGHUP
# ABOUTME: ignored, and survival of abrupt client disconnects (SIGPIPE).
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;
use Time::HiRes ();
use IO::Socket::INET;
use SQE::Test qw(spawn_daemon RT_INFO RT_REPLY);

subtest 'SIGTERM: prompt clean exit' => sub {
	my $d = spawn_daemon();
	kill 'TERM', $d->pid;
	my $t0 = Time::HiRes::time();
	my $status = $d->wait_exit(5);
	ok(defined $status, 'daemon exited');
	is($status, 0, 'exit status 0');
	cmp_ok(Time::HiRes::time() - $t0, '<', 2, 'exit was prompt');
};

subtest 'SIGINT: prompt clean exit' => sub {
	my $d = spawn_daemon();
	kill 'INT', $d->pid;
	is($d->wait_exit(5), 0, 'exit status 0');
};

subtest 'SIGHUP: ignored, daemon keeps answering' => sub {
	my $d = spawn_daemon();
	kill 'HUP', $d->pid;
	Time::HiRes::sleep(0.2);
	my $res = $d->request([RT_INFO, 1]);
	is($res->[0], RT_INFO|RT_REPLY, 'still answering after SIGHUP');
};

subtest 'abrupt client disconnect does not kill the daemon' => sub {
	my $d = spawn_daemon();
	# Flood pipelined requests and vanish without reading: replies pile up
	# in the daemon's send buffers, the RST arrives with writes pending,
	# and an unprotected daemon dies of SIGPIPE on Linux.
	$d->multi_request(map { [RT_INFO, $_] } 1 .. 10000);
	close $d->{conn};
	$d->{conn} = undef;
	Time::HiRes::sleep(0.5);
	my $c = IO::Socket::INET->new(
		PeerAddr => '127.0.0.1:' . $d->port, Proto => 'tcp')
		or fail('cannot reconnect to flooded daemon'), return;
	$d->{conn} = $c;
	my $res = $d->request([RT_INFO, 2]);
	is($res->[0], RT_INFO|RT_REPLY, 'daemon alive and answering after client vanished');
};

done_testing;
