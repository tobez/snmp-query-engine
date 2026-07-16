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
use Time::HiRes ();

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

{
	my $info = $d->request([RT_INFO, 100])->[2];
	is($info->{global}{v3_engineid_discoveries}, 0, 'v3_engineid_discoveries starts at 0');
	is($info->{global}{v3_engineid_mismatches}, 0, 'v3_engineid_mismatches starts at 0');
	ok(!exists $info->{connection}{v3_engineid_discoveries}, 'discoveries counter is global-only');
	ok(!exists $info->{connection}{v3_engineid_mismatches}, 'mismatches counter is global-only');
}

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

# probe timeout: held queries fail with plain ["timeout"], nothing else hits the wire
{
	my $asilent = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3, v3_never_sync => 1);
	request_match($d, 'discovery setopt against a silent agent',
		[RT_SETOPT, 520, $target, $asilent->port, {
			version => 3, username => $v3{username},
			authprotocol => 'sha256', authpassword => $v3{auth_pass},
			privprotocol => 'aes128', privpassword => $v3{priv_pass},
			timeout => 100, retries => 2 }],
		[RT_SETOPT|RT_REPLY, 520, T()]);
	my $sends0 = $d->request([RT_INFO, 521])->[2]{global}{snmp_sends};
	request_match($d, 'probe timeout fails all held oids with timeout',
		[RT_GET, 522, $target, $asilent->port,
			['1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.3.0']],
		[RT_GET|RT_REPLY, 522, [
			['1.3.6.1.2.1.1.5.0', ['timeout']],
			['1.3.6.1.2.1.1.3.0', ['timeout']]]]);
	my $sends1 = $d->request([RT_INFO, 523])->[2]{global}{snmp_sends};
	is($sends1 - $sends0, 2, 'only the probe (2 sends) hit the wire, held oids never did');
	request_match($d, 'engineid still empty after probe timeout',
		[RT_GETOPT, 524, $target, $asilent->port],
		[RT_GETOPT|RT_REPLY, 524, {engineid => ''}]);
	$asilent->stop;
}

# discovery happy path: probe, adopt, localize, release held queries
{
	my $ahappy = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3);
	my $disc0 = $d->request([RT_INFO, 530])->[2]{global}{v3_engineid_discoveries};
	request_match($d, 'discovery setopt (happy path)',
		[RT_SETOPT, 531, $target, $ahappy->port, {
			version => 3, username => $v3{username},
			authprotocol => 'sha256', authpassword => $v3{auth_pass},
			privprotocol => 'aes128', privpassword => $v3{priv_pass} }],
		[RT_SETOPT|RT_REPLY, 531, T()]);
	request_match($d, 'v3 authPriv get succeeds via discovered engine id',
		[RT_GET, 532, $target, $ahappy->port, ['1.3.6.1.2.1.1.5.0']],
		[RT_GET|RT_REPLY, 532, [['1.3.6.1.2.1.1.5.0', $hostname]]]);
	my $eid = pack 'H*', $v3{engine_id};
	request_match($d, 'getopt shows discovered engine id and localized keys',
		[RT_GETOPT, 533, $target, $ahappy->port],
		[RT_GETOPT|RT_REPLY, 533, {
			engineid => $v3{engine_id},
			authkul  => unpack('H*', SQE::USM::password_to_kul('sha256', $v3{auth_pass}, $eid)),
			privkul  => unpack('H*', SQE::USM::password_to_kul('sha256', $v3{priv_pass}, $eid)),
		}]);
	my $disc1 = $d->request([RT_INFO, 534])->[2]{global}{v3_engineid_discoveries};
	is($disc1 - $disc0, 1, 'one engine id discovery counted');
	$ahappy->stop;
}

# probe retry: first probe dropped, second one discovers
{
	my $adrop = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3, drop_first => 1);
	request_match($d, 'discovery setopt (drop-first agent)',
		[RT_SETOPT, 540, $target, $adrop->port, {
			version => 3, username => $v3{username},
			authprotocol => 'sha256', authpassword => $v3{auth_pass},
			privprotocol => 'aes128', privpassword => $v3{priv_pass},
			timeout => 100, retries => 3 }],
		[RT_SETOPT|RT_REPLY, 540, T()]);
	request_match($d, 'discovery survives a dropped probe via normal retries',
		[RT_GET, 541, $target, $adrop->port, ['1.3.6.1.2.1.1.5.0']],
		[RT_GET|RT_REPLY, 541, [['1.3.6.1.2.1.1.5.0', $hostname]]]);
	$adrop->stop;
}

# pinned mismatch: wrong pin fast-fails with the agent's claimed engine id
{
	my $amis = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3);
	my $mm0 = $d->request([RT_INFO, 550])->[2]{global}{v3_engineid_mismatches};
	request_match($d, 'pin a wrong engine id',
		[RT_SETOPT, 551, $target, $amis->port, {
			version => 3, engineid => '80001f8804deadbeef',
			username => $v3{username},
			authprotocol => 'sha256', authpassword => $v3{auth_pass},
			privprotocol => 'aes128', privpassword => $v3{priv_pass},
			timeout => 2000, retries => 3 }],
		[RT_SETOPT|RT_REPLY, 551, T()]);
	my $t0 = Time::HiRes::time();
	request_match($d, 'engine id mismatch fails the request fast',
		[RT_GET, 552, $target, $amis->port, ['1.3.6.1.2.1.1.5.0']],
		[RT_GET|RT_REPLY, 552,
			[['1.3.6.1.2.1.1.5.0', ["engine-id-mismatch: $v3{engine_id}"]]]]);
	ok(Time::HiRes::time() - $t0 < 1, 'mismatch failure arrives well under the timeout');
	my $mm1 = $d->request([RT_INFO, 553])->[2]{global}{v3_engineid_mismatches};
	is($mm1 - $mm0, 1, 'one engine id mismatch counted');
	$amis->stop;
}

# discovered-then-pinned: a device swap after discovery fast-fails, and an
# explicit re-setopt without engineid re-discovers
{
	my %v3new = (%v3, engine_id => '80001f88046e657765');
	my $aswap = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3);
	my %opts = (
		version => 3, username => $v3{username},
		authprotocol => 'sha256', authpassword => $v3{auth_pass},
		privprotocol => 'aes128', privpassword => $v3{priv_pass},
		timeout => 2000, retries => 3 );
	request_match($d, 'discovery setopt (device-swap scenario)',
		[RT_SETOPT, 560, $target, $aswap->port, \%opts],
		[RT_SETOPT|RT_REPLY, 560, T()]);
	request_match($d, 'initial discovery works',
		[RT_GET, 561, $target, $aswap->port, ['1.3.6.1.2.1.1.5.0']],
		[RT_GET|RT_REPLY, 561, [['1.3.6.1.2.1.1.5.0', $hostname]]]);
	my $swap_port = $aswap->port;
	$aswap->stop;
	my $aswap2 = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3new, port => $swap_port);
	request_match($d, 'device swap after discovery fast-fails (discovered == pinned)',
		[RT_GET, 562, $target, $swap_port, ['1.3.6.1.2.1.1.5.0']],
		[RT_GET|RT_REPLY, 562,
			[['1.3.6.1.2.1.1.5.0', ["engine-id-mismatch: $v3new{engine_id}"]]]]);
	request_match($d, 're-setopt without engineid triggers re-discovery',
		[RT_SETOPT, 563, $target, $swap_port, \%opts],
		[RT_SETOPT|RT_REPLY, 563, {engineid => ''}]);
	request_match($d, 'get succeeds against the swapped device after re-discovery',
		[RT_GET, 564, $target, $swap_port, ['1.3.6.1.2.1.1.5.0']],
		[RT_GET|RT_REPLY, 564, [['1.3.6.1.2.1.1.5.0', $hostname]]]);
	request_match($d, 'getopt shows the new discovered engine id',
		[RT_GETOPT, 565, $target, $swap_port],
		[RT_GETOPT|RT_REPLY, 565, {engineid => $v3new{engine_id}}]);
	$aswap2->stop;
}

# re-setopt while the probe is in flight: the stale probe's REPORT must not
# adopt (nor fast-fail as a normal sid), and the held query survives to be
# served under the new configuration
{
	my $aslow = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3, delay_ms => 500);
	request_match($d, 'discovery setopt (slow agent)',
		[RT_SETOPT, 570, $target, $aslow->port, {
			version => 3, username => $v3{username},
			authprotocol => 'sha256', authpassword => $v3{auth_pass},
			privprotocol => 'aes128', privpassword => $v3{priv_pass},
			timeout => 1000, retries => 1 }],
		[RT_SETOPT|RT_REPLY, 570, T()]);
	my $g0 = $d->request([RT_INFO, 571])->[2]{global};
	$d->lone_request([RT_GET, 572, $target, $aslow->port, ['1.3.6.1.2.1.1.5.0']]);
	Time::HiRes::sleep(0.15);   # probe is out; its REPORT is still ~350ms away
	request_match($d, 're-pin (to a wrong engine id) while the probe is in flight',
		[RT_SETOPT, 573, $target, $aslow->port, {
			version => 3, engineid => '80001f8804deadbeef', username => $v3{username},
			authprotocol => 'sha256', authpassword => $v3{auth_pass},
			privprotocol => 'aes128', privpassword => $v3{priv_pass},
			timeout => 1000, retries => 3 }],
		[RT_SETOPT|RT_REPLY, 573, T()]);
	my ($get) = $d->bulk_response;
	is($get, to_check([RT_GET|RT_REPLY, 572,
			[['1.3.6.1.2.1.1.5.0', ["engine-id-mismatch: $v3{engine_id}"]]]]),
		'held query survives the re-setopt and fails under the new pin, not as a probe timeout');
	my $g1 = $d->request([RT_INFO, 574])->[2]{global};
	is($g1->{v3_engineid_discoveries} - $g0->{v3_engineid_discoveries}, 0,
		'the stale probe reply did not adopt');
	is($g1->{v3_engineid_mismatches} - $g0->{v3_engineid_mismatches}, 1,
		'only the real query fast-failed; the stale probe reply was plain-ignored');
	request_match($d, 'engine id is the re-pinned one, untouched by the stale probe',
		[RT_GETOPT, 575, $target, $aslow->port],
		[RT_GETOPT|RT_REPLY, 575, {engineid => '80001f8804deadbeef'}]);
	$aslow->stop;
}

# empty-engineid reply during discovery: a bogus GET-RESPONSE carrying an empty
# authoritative engineID matches the (empty) stored one and so bypasses the
# mismatch branch. It must be ignored, never processed as a GET reply nor allowed
# to strand the discovery state so future queries hang.
{
	my $abogus = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3, v3_empty_eid_reply => 1);
	request_match($d, 'discovery setopt (empty-eid-reply agent)',
		[RT_SETOPT, 580, $target, $abogus->port, {
			version => 3, username => $v3{username},
			authprotocol => 'sha256', authpassword => $v3{auth_pass},
			privprotocol => 'aes128', privpassword => $v3{priv_pass},
			timeout => 100, retries => 2 }],
		[RT_SETOPT|RT_REPLY, 580, T()]);
	my $g0 = $d->request([RT_INFO, 581])->[2]{global};
	request_match($d, 'bogus empty-eid reply is ignored; get times out',
		[RT_GET, 582, $target, $abogus->port, ['1.3.6.1.2.1.1.5.0']],
		[RT_GET|RT_REPLY, 582, [['1.3.6.1.2.1.1.5.0', ['timeout']]]]);
	my $g1 = $d->request([RT_INFO, 583])->[2]{global};
	is($g1->{v3_engineid_discoveries} - $g0->{v3_engineid_discoveries}, 0,
		'the bogus empty-eid reply did not adopt an engine id');
	ok($g1->{snmp_sends} - $g0->{snmp_sends} >= 2,
		'the first get sent probe traffic (initial + retry)');
	request_match($d, 'engineid still empty after the bogus reply',
		[RT_GETOPT, 584, $target, $abogus->port],
		[RT_GETOPT|RT_REPLY, 584, {engineid => ''}]);
	# a second get must send a NEW probe, not hang forever on a stranded probe_sid
	request_match($d, 'second get still probes (does not hang) and times out',
		[RT_GET, 585, $target, $abogus->port, ['1.3.6.1.2.1.1.5.0']],
		[RT_GET|RT_REPLY, 585, [['1.3.6.1.2.1.1.5.0', ['timeout']]]]);
	my $g2 = $d->request([RT_INFO, 586])->[2]{global};
	ok($g2->{snmp_sends} - $g1->{snmp_sends} >= 2,
		'the second get sent a fresh probe (discovery state was not stranded)');
	$abogus->stop;
}

# ignore-flush frees a live discovery probe: a normal sid timing out and
# tripping ignore_threshold must not strand cri->v3->probe_sid, or every
# later query on that destination hangs forever. (Route A for the
# free_sid_info probe_sid clause; Route B, where the probe itself dies via
# sid_timer and self-clears probe_sid, is covered by the stale-probe test
# above.)
{
	my $asilent = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3, drop_all => 1);
	my $ignport = $asilent->port;

	request_match($d, 'pin v3 creds with a short timeout and ignore_threshold=1',
		[RT_SETOPT, 590, $target, $ignport, {
			version => 3, engineid => $v3{engine_id}, username => $v3{username},
			authprotocol => 'sha256', authpassword => $v3{auth_pass},
			privprotocol => 'aes128', privpassword => $v3{priv_pass},
			timeout => 150, retries => 1,
			ignore_threshold => 1, ignore_duration => 300 }],
		[RT_SETOPT|RT_REPLY, 590, T()]);

	# GET1: a normal (non-probe) sid, sent under the pinned config above.
	$d->lone_request([RT_GET, 591, $target, $ignport, ['1.3.6.1.2.1.1.5.0']]);

	# Re-setopt into discovery mode on the same target/port while GET1's sid
	# is still in flight; its own timeout (500ms) is well past GET1's (150ms)
	# so the probe sent for GET2 below is still alive when GET1 times out.
	request_match($d, 're-setopt to discovery mode while the normal sid is still in flight',
		[RT_SETOPT, 592, $target, $ignport, {
			version => 3, username => $v3{username},
			authprotocol => 'sha256', authpassword => $v3{auth_pass},
			privprotocol => 'aes128', privpassword => $v3{priv_pass},
			timeout => 500, retries => 1 }],
		[RT_SETOPT|RT_REPLY, 592, {engineid => ''}]);

	# GET2: held behind the discovery probe just sent for it.
	$d->lone_request([RT_GET, 593, $target, $ignport, ['1.3.6.1.2.1.1.5.0']]);

	# GET1 times out first and trips ignore_threshold; flush_ignored_destination
	# must free the still-live discovery probe (and clear probe_sid) as part of
	# ignoring GET2's held oid.
	my @got;
	local $SIG{ALRM} = sub { die "timed out waiting for GET1/GET2 replies\n" };
	alarm(3);
	push @got, $d->bulk_response while @got < 2;
	alarm(0);
	my %by_cid = map { ($_->[1], $_) } @got;
	is($by_cid{591}, to_check([RT_GET|RT_REPLY, 591, [['1.3.6.1.2.1.1.5.0', ['timeout']]]]),
		'GET1 times out normally and trips the destination ignore threshold');
	is($by_cid{593}, to_check([RT_GET|RT_REPLY, 593, [['1.3.6.1.2.1.1.5.0', ['ignored']]]]),
		'GET2 (held behind the live probe) is ignored by the same flush');

	Time::HiRes::sleep(0.45);   # past ignore_duration

	local $SIG{ALRM} = sub { die "GET3 hung: stale probe_sid was not cleared by the flush\n" };
	alarm(3);
	request_match($d, 'GET3 after the ignore window still probes and times out, rather than hanging',
		[RT_GET, 594, $target, $ignport, ['1.3.6.1.2.1.1.5.0']],
		[RT_GET|RT_REPLY, 594, [['1.3.6.1.2.1.1.5.0', ['timeout']]]]);
	alarm(0);

	request_match($d, 'engineid is still empty (discovery mode, not stranded)',
		[RT_GETOPT, 595, $target, $ignport],
		[RT_GETOPT|RT_REPLY, 595, {engineid => ''}]);
	ok(kill(0, $d->pid), 'daemon is still alive');

	$asilent->stop;
}

# cipher-truncated privkul, as sent by Net::SNMP-style clients, polls end-to-end
{
	my %v3s = (%v3, auth_proto => 'sha512');
	my $a16 = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3s);
	my $eid = pack 'H*', $v3s{engine_id};
	my $authkul = unpack 'H*', SQE::USM::password_to_kul('sha512', $v3s{auth_pass}, $eid);
	my $privkul = unpack 'H*', SQE::USM::priv_key('sha512', $v3s{priv_pass}, $eid);
	request_match($d, 'setopt accepts a 16-byte privkul with sha512 auth',
		[RT_SETOPT, 700, $target, $a16->port, {
			version => 3, engineid => $v3s{engine_id}, username => $v3s{username},
			authprotocol => 'sha512', authkul => $authkul,
			privprotocol => 'aes128', privkul => $privkul }],
		[RT_SETOPT|RT_REPLY, 700, T()]);
	request_match($d, 'v3 authPriv get succeeds with a cipher-truncated privkul',
		[RT_GET, 701, $target, $a16->port, ['1.3.6.1.2.1.1.5.0']],
		[RT_GET|RT_REPLY, 701, [['1.3.6.1.2.1.1.5.0', $hostname]]]);
	$a16->stop;
}

$d->stop;
done_testing;
