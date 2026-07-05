#!/usr/bin/env perl
# ABOUTME: Integration tests for leveled logging: default/quiet/debug levels,
# ABOUTME: plain timestamped format, and journald <N>-prefix mode.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;
use File::Temp ();
use SQE::Test qw(spawn_daemon RT_INFO RT_REPLY);

my $TS = qr/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[-+]\d{4}/;

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "$path: $!";
	local $/;
	return <$fh>;
}

subtest 'default level: info, plain format' => sub {
	my $log = File::Temp->new;
	my $d = spawn_daemon(args => [], stderr_file => "$log");
	$d->request([RT_INFO, 1]);
	$d->stop;
	my $text = slurp("$log");
	like($text, qr/^time=$TS level=info msg="event loop started" op=(?:epoll|kqueue)$/m,
		'startup line at info with timestamp');
	like($text, qr/^time=$TS level=info msg="incoming connection"/m,
		'connection notice at info');
	unlike($text, qr/level=debug/, 'no debug lines by default');
};

subtest '-q: warnings and errors only' => sub {
	my $log = File::Temp->new;
	my $d = spawn_daemon(args => ['-q'], stderr_file => "$log");
	$d->request([RT_INFO, 1]);
	$d->stop;
	my $text = slurp("$log");
	unlike($text, qr/level=info/, 'info suppressed under -q');
};

subtest '-d: debug enabled' => sub {
	my $log = File::Temp->new;
	my $d = spawn_daemon(args => ['-d'], stderr_file => "$log");
	$d->request([RT_INFO, 1]);
	$d->stop;
	like(slurp("$log"), qr/^time=$TS level=debug msg="debug logging enabled"$/m,
		'debug line present under -d');
};

subtest 'journald mode: <N> prefixes, no timestamps' => sub {
	my $log = File::Temp->new;
	my @st = stat("$log");
	my $d = spawn_daemon(args => [], stderr_file => "$log",
		env => { JOURNAL_STREAM => "$st[0]:$st[1]" });
	$d->request([RT_INFO, 1]);
	$d->stop;
	my $text = slurp("$log");
	like($text, qr/^<6>msg="event loop started" op=(?:epoll|kqueue)$/m,
		'info line carries <6> prefix');
	unlike($text, qr/^$TS/m, 'no timestamps in journald mode');
};

done_testing;
