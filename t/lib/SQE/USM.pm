package SQE::USM;
# ABOUTME: Independent SNMPv3 USM crypto (key localization, HMAC, AES-CFB) for
# ABOUTME: the fake agent — mirrors RFC 3414/3826 and cross-checks SQE's C code.
use strict;
use warnings;
use Digest::SHA qw(sha1 sha224 sha256 sha384 sha512
                   hmac_sha1 hmac_sha224 hmac_sha256 hmac_sha384 hmac_sha512);
use Crypt::Rijndael;

my %DIGEST = (
	sha1 => \&sha1, sha224 => \&sha224, sha256 => \&sha256,
	sha384 => \&sha384, sha512 => \&sha512,
);

my %HMAC = (
	sha1 => \&hmac_sha1, sha224 => \&hmac_sha224, sha256 => \&hmac_sha256,
	sha384 => \&hmac_sha384, sha512 => \&hmac_sha512,
);
my %MACLEN = (sha1 => 12, sha224 => 16, sha256 => 24, sha384 => 32, sha512 => 48);

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

sub maclen { $MACLEN{$_[0]} // die "unknown auth proto $_[0]" }

sub hmac {
	my ($algo, $kul, $msg) = @_;
	my $h = $HMAC{$algo} or die "unknown auth proto $algo";
	return substr($h->($msg, $kul), 0, $MACLEN{$algo});   # Digest::SHA hmac: key is the LAST arg
}

sub priv_key {
	my ($auth_algo, $priv_pass, $engine_id) = @_;
	return substr(password_to_kul($auth_algo, $priv_pass, $engine_id), 0, 16);
}

# AES-CFB128. $mode 'e'/'d'. IV = boots(N) . time(N) . salt(8). Feedback register
# is always the ciphertext block (output when encrypting, input when decrypting).
sub aes_cfb {
	my ($mode, $key, $boots, $time, $salt, $data) = @_;
	my $iv = pack('N', $boots) . pack('N', $time) . $salt;
	my $c  = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_ECB());
	my ($out, $fb) = ('', $iv);
	for (my $i = 0; $i < length $data; $i += 16) {
		my $ks = $c->encrypt($fb);
		my $in = substr($data, $i, 16);
		my $r  = length $in;
		my $ob = $in ^ substr($ks, 0, $r);
		$out  .= $ob;
		my $cipher = $mode eq 'e' ? $ob : $in;
		$fb = substr($cipher . substr($ks, $r), 0, 16);
	}
	return $out;
}

1;
