#!/usr/bin/env perl
# ABOUTME: Verifies the daemon survives transient accept() failures under fd
# ABOUTME: exhaustion, logs a warning, and accepts clients again afterwards.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;
use File::Temp ();
use Time::HiRes ();
use IO::Socket::INET;
use IO::Select;
use Data::MessagePack ();
use SQE::Test qw(spawn_daemon RT_INFO RT_REPLY);

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or return '';
	local $/;
	return scalar <$fh>;
}

my $log = File::Temp->new;
my $d = spawn_daemon(rlimit_nofile => 16, stderr_file => "$log");

# Baseline: the control connection (accepted at spawn time) works.
my $r = $d->request([RT_INFO, 1]);
is($r->[0], RT_INFO|RT_REPLY, 'baseline request works');

# Exhaust the daemon's fds: connect() succeeds regardless (backlog is 1024),
# but the daemon runs out of fds trying to accept().
my @extra;
for (1..24) {
	my $c = IO::Socket::INET->new(
		PeerAddr => '127.0.0.1:' . $d->port,
		Proto    => 'tcp',
		Timeout  => 2,
	);
	push @extra, $c if $c;
}
cmp_ok(scalar @extra, '>', 15, 'opened enough connections to exhaust fds');

# The daemon must log the throttled warning...
my $seen = 0;
for (1..100) {
	$seen = 1, last if slurp("$log") =~ /msg="cannot accept client connection"/;
	Time::HiRes::sleep(0.05);
}
ok($seen, 'accept failure warning logged');
like(slurp("$log"), qr/msg="cannot accept client connection" error=/,
	'warning carries errno detail');

# ...and survive: still running, still serving the existing connection.
ok(kill(0, $d->pid), 'daemon still running under fd exhaustion');
$r = $d->request([RT_INFO, 2]);
is($r->[0], RT_INFO|RT_REPLY, 'existing connection still served');

# Free the fds; the daemon must start accepting new clients again.
close $_ for @extra;
my $mp = Data::MessagePack->new->prefer_integer;
my $recovered = 0;
for (1..100) {
	my $c = IO::Socket::INET->new(
		PeerAddr => '127.0.0.1:' . $d->port,
		Proto    => 'tcp',
		Timeout  => 2,
	);
	if ($c) {
		$c->syswrite($mp->pack([RT_INFO, 3]));
		if (IO::Select->new($c)->can_read(2)) {
			my $buf = '';
			$c->sysread($buf, 65536);
			if (length $buf) {
				my $rr = $mp->unpack($buf);
				if (ref $rr eq 'ARRAY' && $rr->[0] == (RT_INFO|RT_REPLY)) {
					$recovered = 1;
					close $c;
					last;
				}
			}
		}
		close $c;
	}
	Time::HiRes::sleep(0.05);
}
ok($recovered, 'new connections accepted after fds freed');

$d->stop;
done_testing;
