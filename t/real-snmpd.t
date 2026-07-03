#! /usr/bin/perl
# ABOUTME: Opt-in sanity tests against a real SNMP agent (set SQE_REAL_SNMPD=1).
# ABOUTME: Target and credentials come from SQE_SNMPD_* environment variables.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;
use SQE::Test ':all';

skip_all "set SQE_REAL_SNMPD=1 (and SQE_SNMPD_HOST/PORT/COMMUNITY/V3_* as needed) to run"
	unless $ENV{SQE_REAL_SNMPD};

my $host      = $ENV{SQE_SNMPD_HOST}      // '127.0.0.1';
my $port      = $ENV{SQE_SNMPD_PORT}      // 161;
my $community = $ENV{SQE_SNMPD_COMMUNITY} // 'public';

my $d = spawn_daemon();

request_match($d, "set community", [RT_SETOPT, 100, $host, $port, {community => $community}],
	[RT_SETOPT|RT_REPLY, 100, T()]);

# shape assertions only: the agent's data is not ours
my $r = request_match($d, "v2c get sysName+sysUpTime",
	[RT_GET, 101, $host, $port, ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.3.0"]],
	[RT_GET|RT_REPLY, 101, [
		["1.3.6.1.2.1.1.5.0", match qr/./],
		["1.3.6.1.2.1.1.3.0", match qr/^\d+$/]]]);

$r = request_match($d, "v2c ifDescr walk",
	[RT_GETTABLE, 102, $host, $port, "1.3.6.1.2.1.2.2.1.2"],
	[RT_GETTABLE|RT_REPLY, 102, T()]);
ok(@{$r->[2]} > 0, "walk returned at least one row");
my @oids = map { $_->[0] } @{$r->[2]};
is([sort { SQE::Test::oid_cmp($a, $b) } @oids], \@oids, "row OIDs strictly increasing");

if (my $user = $ENV{SQE_SNMPD_V3_USER}) {
	my %v3 = (
		version      => 3,
		username     => $user,
		authprotocol => $ENV{SQE_SNMPD_V3_AUTH_PROTO} // 'sha1',
		authpassword => $ENV{SQE_SNMPD_V3_AUTH_PASS},
	);
	if ($ENV{SQE_SNMPD_V3_PRIV_PASS}) {
		$v3{privprotocol} = $ENV{SQE_SNMPD_V3_PRIV_PROTO} // 'aes128';
		$v3{privpassword} = $ENV{SQE_SNMPD_V3_PRIV_PASS};
	}
	request_match($d, "set v3 credentials", [RT_SETOPT, 200, $host, $port, \%v3],
		[RT_SETOPT|RT_REPLY, 200, T()]);
	request_match($d, "v3 get sysName",
		[RT_GET, 201, $host, $port, ["1.3.6.1.2.1.1.5.0"]],
		[RT_GET|RT_REPLY, 201, [["1.3.6.1.2.1.1.5.0", match qr/./]]]);
} else {
	note "SQE_SNMPD_V3_USER not set, skipping v3 checks";
}

$d->stop;
done_testing;
