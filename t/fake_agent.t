#! /usr/bin/perl
# ABOUTME: Self-test for SQE::FakeAgent: byte-level known-answer checks of the
# ABOUTME: BER codec plus GET/GETNEXT/GETBULK semantics and misbehavior knobs.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;
use IO::Socket::INET;
use IO::Select;
use SQE::FakeAgent;

sub udp_exchange {
	my ($port, $bytes, $timeout) = @_;
	$timeout //= 2;
	my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port", Proto => 'udp')
		or die "udp socket: $!";
	$s->send($bytes);
	my $sel = IO::Select->new($s);
	return undef unless $sel->can_read($timeout);
	$s->recv(my $reply, 65535);
	return $reply;
}

my @tree = (
	['1.3.6.1.2.1.1.5.0',      str => 'fake'],
	['1.3.6.1.2.1.2.2.1.2.1',  str => 'lo0'],
	['1.3.6.1.2.1.2.2.1.2.2',  str => 'em0'],
	['1.3.6.1.2.1.25.1.1.0',   ticks => 123456],
);

# Hand-assembled v2c GET of sysName.0 (community public, request-id 1)
my $get_sysname = pack 'H*',
	'302602010104067075626c6963a019020101020100020100300e300c06082b060102010105000500';
# Expected reply: same envelope, RESPONSE pdu, sysName.0 = "fake"
my $expect_reply = pack 'H*',
	'302a02010104067075626c6963a21d02010102010002010030123010' .
	'06082b060102010105000404' . unpack('H*', 'fake');

my $agent = SQE::FakeAgent->spawn(tree => \@tree);
ok($agent->port > 0, "agent reports a port");

is(unpack('H*', udp_exchange($agent->port, $get_sysname) // ''),
	unpack('H*', $expect_reply),
	"v2c GET sysName.0: byte-exact known-answer reply");

# Semantic checks ride on the module codec for request construction.
sub build_req {
	my ($pdu_tag, $version, $f1, $f2, @oids) = @_;
	my $vbl = join '', map {
		SQE::FakeAgent::_tlv(0x30,
			SQE::FakeAgent::_tlv(0x06, SQE::FakeAgent::_enc_oid_content($_))
			. SQE::FakeAgent::_tlv(0x05, ''))
	} @oids;
	my $pdu = SQE::FakeAgent::_tlv($pdu_tag,
		SQE::FakeAgent::_enc_uint(0x02, 42)
		. SQE::FakeAgent::_enc_uint(0x02, $f1)
		. SQE::FakeAgent::_enc_uint(0x02, $f2)
		. SQE::FakeAgent::_tlv(0x30, $vbl));
	return SQE::FakeAgent::_tlv(0x30,
		SQE::FakeAgent::_enc_uint(0x02, $version)
		. SQE::FakeAgent::_tlv(0x04, 'public') . $pdu);
}

sub parse_varbinds {   # returns [oid, tag, raw-content] triples from a reply
	my ($reply) = @_;
	my ($t, $msg) = SQE::FakeAgent::_get_tlv($reply, 0);
	my $pos = 0;
	(undef, undef, $pos) = SQE::FakeAgent::_get_tlv($msg, $pos);  # version
	(undef, undef, $pos) = SQE::FakeAgent::_get_tlv($msg, $pos);  # community
	(my $ptag, my $pdu) = SQE::FakeAgent::_get_tlv($msg, $pos);
	$pos = 0;
	(undef, undef, $pos) = SQE::FakeAgent::_get_tlv($pdu, $pos);  # reqid
	(undef, my $errst, $pos) = SQE::FakeAgent::_get_tlv($pdu, $pos);
	(undef, undef, $pos) = SQE::FakeAgent::_get_tlv($pdu, $pos);  # erridx
	(undef, my $vbl, $pos) = SQE::FakeAgent::_get_tlv($pdu, $pos);
	my @vb;
	my $vpos = 0;
	while ($vpos < length $vbl) {
		(undef, my $vb, $vpos) = SQE::FakeAgent::_get_tlv($vbl, $vpos);
		my ($ot, $oc, $op) = SQE::FakeAgent::_get_tlv($vb, 0);
		my ($vt, $vc) = SQE::FakeAgent::_get_tlv($vb, $op);
		push @vb, [SQE::FakeAgent::_dec_oid($oc), $vt, $vc];
	}
	return (SQE::FakeAgent::_dec_uint($errst), @vb);
}

# GETNEXT walks in tree order
my ($errst, @vb) = parse_varbinds(udp_exchange($agent->port,
	build_req(0xa1, 1, 0, 0, '1.3.6.1.2.1.2.2.1.2')));
is($errst, 0, "getnext: no error");
is($vb[0][0], '1.3.6.1.2.1.2.2.1.2.1', "getnext from table oid yields first row");

# GETBULK reaches endOfMibView past the last entry
($errst, @vb) = parse_varbinds(udp_exchange($agent->port,
	build_req(0xa5, 1, 0, 10, '1.3.6.1.2.1.25.1.1.0')));
is($vb[0][1], 0x82, "getbulk past end: endOfMibView");

# v1 GET of a missing oid: noSuchName
($errst, @vb) = parse_varbinds(udp_exchange($agent->port,
	build_req(0xa0, 0, 0, 0, '1.3.66')));
is($errst, 2, "v1 get of missing oid: noSuchName error-status");

# wrong community: silence
# edits the community bytes in place (same length: "public" and "secret"
# are both 6 bytes, so the BER length prefix stays valid)
is(udp_exchange($agent->port, build_req(0xa0, 1, 0, 0, '1.3.6.1.2.1.1.5.0')
	=~ s/public/secret/r, 0.5), undef, "wrong community is dropped");
$agent->stop;

# repeat_oid: walk stops advancing
my $stuck = SQE::FakeAgent->spawn(tree => \@tree, repeat_oid => '1.3.6.1.2.1.2.2.1.2.2');
($errst, @vb) = parse_varbinds(udp_exchange($stuck->port,
	build_req(0xa1, 1, 0, 0, '1.3.6.1.2.1.2.2.1.2.2')));
is($vb[0][0], '1.3.6.1.2.1.2.2.1.2.2', "repeat_oid: getnext does not advance");
$stuck->stop;

# drop_first: first request unanswered, second answered
my $droppy = SQE::FakeAgent->spawn(tree => \@tree, drop_first => 1);
is(udp_exchange($droppy->port, $get_sysname, 0.5), undef, "drop_first: first request dropped");
ok(defined udp_exchange($droppy->port, $get_sysname), "drop_first: second request answered");
$droppy->stop;

# malformed => truncate: reply is a prefix of the valid reply
my $trunc = SQE::FakeAgent->spawn(tree => \@tree, malformed => 'truncate');
my $treply = udp_exchange($trunc->port, $get_sysname);
ok(defined $treply && length($treply) == int(length($expect_reply) / 2)
	&& $treply eq substr($expect_reply, 0, length $treply),
	"truncate: reply is the first half of the valid reply");
$trunc->stop;

# ---- v3 engine id dialect ----

my %v3 = (
	engine_id  => '80001f88047371656369',
	username   => 'sqetest',
	auth_proto => 'sha256', auth_pass => 'sqeauthpass12',
	priv_proto => 'aes128', priv_pass => 'sqeprivpass12',
	boots => 7, time => 1234,
);
my $eid = pack 'H*', $v3{engine_id};

sub build_probe {   # RFC 3414 discovery probe shape (noAuthNoPriv GET, no varbinds)
	my ($mid, %over) = @_;
	my $pdu = SQE::FakeAgent::_tlv(0xa0,
		SQE::FakeAgent::_enc_uint(0x02, $mid)
		. SQE::FakeAgent::_enc_uint(0x02, 0)
		. SQE::FakeAgent::_enc_uint(0x02, 0)
		. SQE::FakeAgent::_tlv(0x30, ''));
	my $peid = $over{eid} // '';
	return SQE::FakeAgent->_build_v3(
		mid => $mid, flags => 0x04, boots => 0, time => 0,
		authenticated => 0, encrypted => 0, privp => '',
		eid => $peid, username => $over{username} // '',
		scoped => SQE::FakeAgent->_scoped($peid, $pdu),
	);
}

sub report_oid_of {   # -> (parsed envelope, pdu tag, first varbind OID)
	my ($reply) = @_;
	my $r = SQE::FakeAgent->_parse_v3($reply);
	# spd is the content of a SEQUENCE (for unencrypted) or OCTET STRING (for encrypted)
	# For REPORT which is noAuthNoPriv, it's unencrypted (SEQUENCE content)
	my $scoped = SQE::FakeAgent::_tlv($r->{spd_tag}, $r->{spd});
	my (undef, $seq) = SQE::FakeAgent::_get_tlv($scoped, 0);
	my $bp = 0;
	(undef, undef, $bp) = SQE::FakeAgent::_get_tlv($seq, $bp);   # ctxEngineID
	(undef, undef, $bp) = SQE::FakeAgent::_get_tlv($seq, $bp);   # ctxName
	(my $ptag, my $pdu, $bp) = SQE::FakeAgent::_get_tlv($seq, $bp);
	my $pp = 0;
	(undef, undef, $pp) = SQE::FakeAgent::_get_tlv($pdu, $pp);   # request-id
	(undef, undef, $pp) = SQE::FakeAgent::_get_tlv($pdu, $pp);   # error-status
	(undef, undef, $pp) = SQE::FakeAgent::_get_tlv($pdu, $pp);   # error-index
	(undef, my $vbl, $pp) = SQE::FakeAgent::_get_tlv($pdu, $pp);
	(undef, my $vb) = SQE::FakeAgent::_get_tlv($vbl, 0);
	(undef, my $oid_c) = SQE::FakeAgent::_get_tlv($vb, 0);
	return ($r, $ptag, SQE::FakeAgent::_dec_oid($oid_c));
}

my $v3agent = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3);

# discovery probe (empty engine id) draws an unknown-engine REPORT with the real engine id
my ($r, $ptag, $roid) = report_oid_of(udp_exchange($v3agent->port, build_probe(101)));
is($ptag, 0xa8, 'probe reply is a REPORT');
is($roid, '1.3.6.1.6.3.15.1.1.4.0', 'probe draws usmStatsUnknownEngineIDs');
is(unpack('H*', $r->{eid}), $v3{engine_id}, 'REPORT carries the agent engine id');
is($r->{boots}, 7, 'REPORT carries agent boots');
is($r->{time}, 1234, 'REPORT carries agent time');
is($r->{flags} & 0x03, 0, 'REPORT is noAuthNoPriv');

# engine id is checked before the username
($r, $ptag, $roid) = report_oid_of(udp_exchange($v3agent->port,
	build_probe(102, eid => $eid . "\x01", username => 'nosuchuser')));
is($roid, '1.3.6.1.6.3.15.1.1.4.0',
	'wrong engine id + wrong user -> unknown-engine, not unknown-user');

my $chosen = $v3agent->port;
$v3agent->stop;

# fixed-port spawn (device-swap scenarios respawn on the same port)
my $fixed = SQE::FakeAgent->spawn(tree => \@tree, v3 => \%v3, port => $chosen);
is($fixed->port, $chosen, 'spawn honors a fixed port');
$fixed->stop;

done_testing;
