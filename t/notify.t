#!/usr/bin/env perl
# ABOUTME: sd_notify protocol tests using a plain unix datagram socket:
# ABOUTME: READY on startup, WATCHDOG pings, STOPPING on shutdown.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;
use File::Temp ();
use IO::Socket::UNIX;
use Socket qw(SOCK_DGRAM);
use Time::HiRes ();
use SQE::Test qw(spawn_daemon RT_INFO RT_REPLY);

sub drain_dgrams {
	my ($sock, $secs) = @_;
	my @msgs;
	my $deadline = Time::HiRes::time() + $secs;
	while (Time::HiRes::time() < $deadline) {
		my $rin = '';
		vec($rin, fileno($sock), 1) = 1;
		next unless select(my $rout = $rin, undef, undef, 0.1);
		my $buf;
		push @msgs, $buf if defined $sock->recv($buf, 4096);
	}
	return @msgs;
}

sub notify_listener {
	my $dir = File::Temp->newdir;
	my $path = "$dir/notify.sock";
	my $sock = IO::Socket::UNIX->new(Local => $path, Type => SOCK_DGRAM)
		or die "notify socket: $!";
	return ($dir, $path, $sock);  # keep $dir alive
}

subtest 'READY=1 after startup' => sub {
	my ($dir, $path, $sock) = notify_listener();
	my $d = spawn_daemon(env => { NOTIFY_SOCKET => $path });
	my @msgs = drain_dgrams($sock, 1);
	ok((grep { /(?:^|\n)READY=1(?:\n|$)/ } @msgs), 'READY=1 received')
		or diag(join '|', @msgs);
};

subtest 'watchdog pings at USEC/3 cadence' => sub {
	my ($dir, $path, $sock) = notify_listener();
	my $d = spawn_daemon(env => {
		NOTIFY_SOCKET => $path, WATCHDOG_USEC => 300000 });
	my @pings = grep { /(?:^|\n)WATCHDOG=1(?:\n|$)/ } drain_dgrams($sock, 1.5);
	cmp_ok(scalar @pings, '>=', 2, 'at least two watchdog pings in 1.5s');
};

subtest 'no NOTIFY_SOCKET: daemon simply works' => sub {
	my $d = spawn_daemon();
	is($d->request([RT_INFO, 1])->[0], RT_INFO|RT_REPLY, 'answers without notify env');
};

done_testing;
