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
use SQE::USM;

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

# never_sync: the agent ignores all v3 requests, so the GET times out.
{
	my $a2 = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3, v3_never_sync => 1);
	request_match($d, 'v3 set creds (never_sync agent)',
		[RT_SETOPT, 300, $target, $a2->port, {
			version => 3, engineid => $v3{engine_id}, username => $v3{username},
			authprotocol => 'sha256', authpassword => $v3{auth_pass},
			privprotocol => 'aes128', privpassword => $v3{priv_pass},
			timeout => 100, retries => 1 }],
		[RT_SETOPT|RT_REPLY, 300, T()]);
	request_match($d, 'v3 get times out when agent never syncs',
		[RT_GET, 301, $target, $a2->port, ['1.3.6.1.2.1.1.5.0']],
		[RT_GET|RT_REPLY, 301, [['1.3.6.1.2.1.1.5.0', ['timeout']]]]);
}

# wrong-password: agent replies usmStatsWrongDigests -> SQE drops, bad_snmp_responses climbs.
{
	my $a3 = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3);
	my $before = $d->request([RT_INFO, 310])->[2]{global}{bad_snmp_responses};
	request_match($d, 'v3 set WRONG password',
		[RT_SETOPT, 311, $target, $a3->port, {
			version => 3, engineid => $v3{engine_id}, username => $v3{username},
			authprotocol => 'sha256', authpassword => 'WRONGwrongWRONG',
			privprotocol => 'aes128', privpassword => $v3{priv_pass},
			timeout => 100, retries => 1 }],
		[RT_SETOPT|RT_REPLY, 311, T()]);
	request_match($d, 'v3 get with wrong password fails',
		[RT_GET, 312, $target, $a3->port, ['1.3.6.1.2.1.1.5.0']],
		[RT_GET|RT_REPLY, 312, [['1.3.6.1.2.1.1.5.0', ['timeout']]]]);
	my $after = $d->request([RT_INFO, 313])->[2]{global}{bad_snmp_responses};
	ok($after > $before, 'wrong-digests report bumped bad_snmp_responses');
}

# reply-integrity faults: SQE must reject a well-formed but tampered reply.
my @faults = qw(bad_hmac engine_id username);
for my $i (0 .. $#faults) {
	my $fault = $faults[$i];
	my $base  = 400 + 10 * $i;
	my $af = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3, v3_reply_fault => $fault);
	request_match($d, "v3 set creds ($fault agent)",
		[RT_SETOPT, $base, $target, $af->port, {
			version => 3, engineid => $v3{engine_id}, username => $v3{username},
			authprotocol => 'sha256', authpassword => $v3{auth_pass},
			privprotocol => 'aes128', privpassword => $v3{priv_pass},
			timeout => 100, retries => 1 }],
		[RT_SETOPT|RT_REPLY, $base, T()]);
	my $before = $d->request([RT_INFO, $base + 1])->[2]{global}{bad_snmp_responses};
	request_match($d, "v3 get fails under $fault",
		[RT_GET, $base + 2, $target, $af->port, ['1.3.6.1.2.1.1.5.0']],
		[RT_GET|RT_REPLY, $base + 2, [['1.3.6.1.2.1.1.5.0', ['timeout']]]]);
	my $after = $d->request([RT_INFO, $base + 3])->[2]{global}{bad_snmp_responses};
	ok($after > $before, "$fault reply bumped bad_snmp_responses");
}

# ---- engine id discovery: setopt semantics ----

# localized keys cannot be re-localized: engineid is mandatory with kuls
{
	my $eid = pack 'H*', $v3{engine_id};
	my $authkul = unpack 'H*', SQE::USM::password_to_kul('sha256', $v3{auth_pass}, $eid);
	my $privkul = unpack 'H*', SQE::USM::password_to_kul('sha256', $v3{priv_pass}, $eid);
	request_match($d, 'authkul without engineid is a setopt error',
		[RT_SETOPT, 500, $target, $port, {
			version => 3, username => $v3{username},
			authprotocol => 'sha256', authkul => $authkul,
			privprotocol => 'aes128', privpassword => $v3{priv_pass} }],
		[RT_SETOPT|RT_ERROR, 500, qr{engineid is required with authkul/privkul}]);
	request_match($d, 'privkul without engineid is a setopt error',
		[RT_SETOPT, 501, $target, $port, {
			version => 3, username => $v3{username},
			authprotocol => 'sha256', authpassword => $v3{auth_pass},
			privprotocol => 'aes128', privkul => $privkul }],
		[RT_SETOPT|RT_ERROR, 501, qr{engineid is required with authkul/privkul}]);
}

# discovery mode: setopt without engineid + passwords is accepted, keys deferred
{
	my $adisc = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3);
	request_match($d, 'setopt without engineid enters discovery mode',
		[RT_SETOPT, 510, $target, $adisc->port, {
			version => 3, username => $v3{username},
			authprotocol => 'sha256', authpassword => $v3{auth_pass},
			privprotocol => 'aes128', privpassword => $v3{priv_pass} }],
		[RT_SETOPT|RT_REPLY, 510, {engineid => '', authkul => '', privkul => ''}]);
	request_match($d, 'getopt before first query: engineid and kuls empty',
		[RT_GETOPT, 511, $target, $adisc->port],
		[RT_GETOPT|RT_REPLY, 511, {engineid => '', authkul => '', privkul => ''}]);
	$adisc->stop;
}

# a setopt with no v3 option keys at all must leave an existing v3 config
# untouched, not rebuild or drop it
{
	my $before = $d->request([RT_GETOPT, 520, $target, $port]);
	request_match($d, 'setopt with only non-v3 options',
		[RT_SETOPT, 521, $target, $port, {timeout => 1500, max_reply_size => 800}],
		[RT_SETOPT|RT_REPLY, 521, T()]);
	my $after = $d->request([RT_GETOPT, 522, $target, $port]);
	is($after->[2]{username},     $before->[2]{username},     'username survives v3-keyless setopt');
	is($after->[2]{engineid},     $before->[2]{engineid},     'engineid survives v3-keyless setopt');
	is($after->[2]{authprotocol}, $before->[2]{authprotocol}, 'authprotocol survives v3-keyless setopt');
	is($after->[2]{authkul},      $before->[2]{authkul},      'authkul survives v3-keyless setopt');
	is($after->[2]{privprotocol}, $before->[2]{privprotocol}, 'privprotocol survives v3-keyless setopt');
	is($after->[2]{privkul},      $before->[2]{privkul},      'privkul survives v3-keyless setopt');
	is($after->[2]{timeout}, 1500, 'non-v3 option still applied by the same setopt');
}

$d->stop;
done_testing;
