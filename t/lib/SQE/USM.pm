package SQE::USM;
# ABOUTME: Independent SNMPv3 USM crypto (key localization, HMAC, AES-CFB) for
# ABOUTME: the fake agent — mirrors RFC 3414/3826 and cross-checks SQE's C code.
use strict;
use warnings;
use Digest::SHA qw(sha1 sha224 sha256 sha384 sha512);

my %DIGEST = (
	sha1 => \&sha1, sha224 => \&sha224, sha256 => \&sha256,
	sha384 => \&sha384, sha512 => \&sha512,
);

sub password_to_key {
	my ($algo, $pass) = @_;
	my $d = $DIGEST{$algo} or die "unknown auth proto $algo";
	die "empty password" unless length $pass;
	my $reps = int(1048576 / length($pass)) + 1;
	return $d->(substr($pass x $reps, 0, 1048576));
}

sub localize_key {
	my ($algo, $ku, $engine_id) = @_;
	my $d = $DIGEST{$algo} or die "unknown auth proto $algo";
	return $d->($ku . $engine_id . $ku);
}

sub password_to_kul {
	my ($algo, $pass, $engine_id) = @_;
	return localize_key($algo, password_to_key($algo, $pass), $engine_id);
}

1;
