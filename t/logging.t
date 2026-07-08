#!/usr/bin/env perl
# ABOUTME: Integration tests for leveled logging: default/quiet/debug levels,
# ABOUTME: plain timestamped format, and journald <N>-prefix mode.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;
use File::Temp ();
use Time::HiRes ();
use SQE::Test qw(spawn_daemon request_match
	RT_SETOPT RT_GET RT_INFO RT_REPLY RT_ERROR);
use SQE::FakeAgent;

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
	$d->{conn}->close;
	Time::HiRes::sleep(0.1);
	$d->stop;
	my $text = slurp("$log");
	like($text, qr/^time=$TS level=info msg="event loop started" op=(?:epoll|kqueue)$/m,
		'startup line at info with timestamp');
	like($text, qr/^time=$TS level=info msg="incoming connection" peer=127\.0\.0\.1:\d+ fd=(\d+)$/m,
		'connection notice carries peer:port and fd');
	my ($fd) = $text =~ /msg="incoming connection" peer=[\d.]+:\d+ fd=(\d+)/;
	like($text, qr/^time=$TS level=info msg="client disconnect" fd=\Q$fd\E$/m,
		'disconnect carries the matching fd');
	unlike($text, qr/level=debug/, 'no debug lines by default');
};

subtest 'startup config summary' => sub {
	my $log = File::Temp->new;
	my $d = spawn_daemon(args => [], stderr_file => "$log");
	my $port = $d->port;
	$d->stop;
	my $text = slurp("$log");
	like($text,
		qr/^time=$TS level=info msg=listening client_addr=127\.0\.0\.1 client_port=\Q$port\E snmp_rcvbuf=\d+ snmp_sndbuf=\d+ max_packets_on_the_wire=1000000 version=\S+$/m,
		'startup line reports bind addr, port, negotiated buffers, limit, version');
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

subtest 'setopt failure leaks no request content' => sub {
	my $log = File::Temp->new;
	my $d = spawn_daemon(args => [], stderr_file => "$log");
	request_match($d, "setopt with secrets fails on bad key",
		[RT_SETOPT, 42, "127.0.0.1", 161, {
			authpassword => "s3cr3tauthpw",
			privpassword => "s3cr3tprivpw",
			meow         => 1,
		}],
		[RT_SETOPT|RT_ERROR, 42, qr/bad option key/]);
	$d->stop;
	my $text = slurp("$log");
	unlike($text, qr/s3cr3tauthpw/, 'auth password not in the log');
	unlike($text, qr/s3cr3tprivpw/, 'priv password not in the log');
	unlike($text, qr/problem handling setopt/, 'setopt-specific warn is gone');
	my @bad = grep { length && !/^time=$TS level=\w+ msg=/ } split /\n/, $text;
	is(\@bad, [], 'every log line is a single logfmt record');
};

subtest 'client request errors logged at debug' => sub {
	my $log = File::Temp->new;
	my $d = spawn_daemon(args => ['-d'], stderr_file => "$log");
	request_match($d, "bad setopt",
		[RT_SETOPT, 7, "127.0.0.1", 161, {meow => 1}],
		[RT_SETOPT|RT_ERROR, 7, qr/bad option key/]);
	request_match($d, "bad get",
		[RT_GET, 8, "127.0.0.1"],
		[RT_GET|RT_ERROR, 8, qr/bad request length/]);
	$d->stop;
	my $text = slurp("$log");
	like($text,
		qr/^time=$TS level=debug msg="client request error" cid=7 code=0x21 error="bad option key"$/m,
		'setopt failure reason at debug');
	like($text,
		qr/^time=$TS level=debug msg="client request error" cid=8 code=0x24 error="bad request length"$/m,
		'get failure reason at debug (funnel covers all request types)');
};

subtest 'sid_info warns carry peer' => sub {
	my $agent = SQE::FakeAgent->spawn(
		tree     => [['1.3.6.1.2.1.1.5.0', str => 'fake']],
		omit_oid => '1.3.6.1.2.1.1.6.0');
	my $aport = $agent->port;
	my $log = File::Temp->new;
	my $d = spawn_daemon(args => [], stderr_file => "$log");
	request_match($d, "setopt v2c to fake agent",
		[RT_SETOPT, 1, "127.0.0.1", $aport, {version => 2}],
		[RT_SETOPT|RT_REPLY, 1, T()]);
	request_match($d, "get with an omitted oid",
		[RT_GET, 2, "127.0.0.1", $aport,
			["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.6.0"]],
		[RT_GET|RT_REPLY, 2, T()]);
	$d->stop;
	$agent->stop;
	like(slurp("$log"),
		qr/^time=$TS level=warn msg="not all oids accounted for" peer=127\.0\.0\.1:$aport sid=\d+$/m,
		'warn carries peer and sid');
};

subtest 'shutdown reason' => sub {
	my $log = File::Temp->new;
	my $d = spawn_daemon(args => [], stderr_file => "$log");
	$d->stop;   # sends SIGTERM (kill 15) and reaps
	like(slurp("$log"),
		qr/^time=$TS level=info msg="shutting down" signal=SIGTERM$/m,
		'shutdown line names the signal that triggered it');
};

subtest 'per-destination anomaly logs coalesce' => sub {
	my $log = File::Temp->new;
	my $d = spawn_daemon(args => [], stderr_file => "$log");
	my $agent = SQE::FakeAgent->spawn(
		tree      => [['1.3.6.1.2.1.1.5.0', str => 'x']],
		malformed => 'garbage',
	);
	my $port = $agent->port;
	# fast timeout + retries so several garbage replies arrive within one window
	$d->request([RT_SETOPT, 1, "127.0.0.1", $port, {timeout => 50, retries => 2}]);
	for my $id (2 .. 4) {
		$d->request([RT_GET, $id, "127.0.0.1", $port, ["1.3.6.1.2.1.1.5.0"]]);
	}
	$d->stop;
	my $text = slurp("$log");
	my @immediate = $text =~ /msg="bad SNMP packet, ignoring"[^\n]*trace=/g;
	is(scalar @immediate, 1,
		'repeated bad-packet anomalies from one agent coalesce to a single immediate line');
};

subtest 'client churn notices coalesce' => sub {
	my $log = File::Temp->new;
	my $d = spawn_daemon(args => [], stderr_file => "$log");   # opens connection #1
	my $port = $d->port;
	my @extra;
	for (1 .. 3) {
		my $c = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port", Proto => "tcp")
			or die "connect: $!";
		push @extra, $c;
	}
	Time::HiRes::sleep(0.1);
	$_->close for @extra;
	Time::HiRes::sleep(0.1);
	$d->stop;
	my $text = slurp("$log");
	my @conn = $text =~ /msg="incoming connection" peer=\S+ fd=\d+/g;
	my @disc = $text =~ /msg="client disconnect" fd=\d+/g;
	is(scalar @conn, 1, 'repeated incoming connections coalesce to one immediate line');
	is(scalar @disc, 1, 'repeated client disconnects coalesce to one immediate line');
};

done_testing;
