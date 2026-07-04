#! /usr/bin/perl
# ABOUTME: A v3 reply whose msg-id matches no outstanding request must be
# ABOUTME: ignored, not crash the daemon (regression test for a NULL deref).
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;
use IO::Socket::INET;
use SQE::Test ':all';

# ---- minimal BER helpers (tag, length, content) ----

sub ber_len {
	my ($n) = @_;
	return chr($n) if $n < 0x80;
	my $b = '';
	while ($n) { $b = chr($n & 0xff) . $b; $n >>= 8 }
	return chr(0x80 | length $b) . $b;
}

sub ber_tlv {
	my ($tag, $content) = @_;
	return chr($tag) . ber_len(length $content) . $content;
}

sub ber_int {
	my ($n) = @_;
	my @b;
	do { unshift @b, $n & 0xff; $n >>= 8 } while ($n);
	unshift @b, 0 if $b[0] & 0x80;
	return ber_tlv(0x02, join '', map chr, @b);
}

sub ber_octets { return ber_tlv(0x04, $_[0]) }
sub ber_sequence { return ber_tlv(0x30, $_[0]) }

# ---- craft a v3 reply with an msg-id matching nothing outstanding ----

my $engineid_hex = "80001f88047371656369";
my $engineid_bin = pack("H*", $engineid_hex);

my $usm_security_params = ber_sequence(
	ber_octets($engineid_bin)  # engine-id
	. ber_int(1)               # engine-boots
	. ber_int(1)               # engine-time
	. ber_octets("whatever")   # username
	. ber_octets("")           # auth-param
	. ber_octets("")           # priv-param
);

my $msg_global_data = ber_sequence(
	ber_int(12345)     # msgID: nonzero, matches no outstanding request
	. ber_int(65000)   # msgMaxSize
	. ber_octets("\x00") # msgFlags: noAuthNoPriv
	. ber_int(3)       # msgSecurityModel: USM
);

my $late_v3_reply = ber_sequence(
	ber_int(3)         # msgVersion
	. $msg_global_data
	. ber_octets($usm_security_params)
);

# ---- set up a plain UDP socket to play the "agent" ----

my $sock = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0, Proto => 'udp')
	or die "cannot create UDP socket: $!";
my $target = "127.0.0.1";
my $port   = $sock->sockport;

my $d = spawn_daemon();

request_match($d, "set v3 credentials",
	[RT_SETOPT, 1, $target, $port, {
		version      => 3,
		engineid     => $engineid_hex,
		username     => "sqetest",
		authprotocol => "sha512",
		authpassword => "sqeauthpass12",
		privprotocol => "aes128",
		privpassword => "sqeprivpass12",
		timeout      => 100,
		retries      => 1,
	}],
	[RT_SETOPT|RT_REPLY, 1, T()]);

$d->lone_request([RT_GET, 2, $target, $port, ["1.3.6.1.2.1.1.5.0"]]);

# wait for the daemon's outbound v3 GET datagram, so the reply below arrives
# from a source ip:port that matches the destination
my $peer = $sock->recv(my $outbound, 65535);
ok(defined $peer, "received the daemon's outbound v3 GET datagram");

$sock->send($late_v3_reply, 0, $peer);

# the daemon must survive: a follow-up request must still get a reply
request_match($d, "daemon survived the unmatched v3 reply",
	[RT_INFO, 3],
	[RT_INFO|RT_REPLY, 3, T()]);

$d->stop;
done_testing;
