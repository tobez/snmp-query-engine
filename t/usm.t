#! /usr/bin/perl
# ABOUTME: Unit tests for SQE::USM — SNMPv3 key localization, HMAC, and AES-CFB
# ABOUTME: checked against RFC 3414 known-answer vectors and round-trips.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2::V0;
use SQE::USM;

# RFC 3414 Appendix A.3.1 SHA-1 vector, password "maplesyrup".
my $eid = pack('H*', '000000000000000000000002');
is(unpack('H*', SQE::USM::password_to_key('sha1', 'maplesyrup')),
	'9fb5cc0381497b3793528939ff788d5d79145211', 'SHA1 Ku matches RFC 3414 A.3.1');
is(unpack('H*', SQE::USM::localize_key('sha1', SQE::USM::password_to_key('sha1', 'maplesyrup'), $eid)),
	'6695febc9288e36282235fc7151f128497b38f3f', 'SHA1 Kul matches RFC 3414 A.3.1');
is(unpack('H*', SQE::USM::password_to_kul('sha1', 'maplesyrup', $eid)),
	'6695febc9288e36282235fc7151f128497b38f3f', 'password_to_kul composes the two');

# MAC truncation lengths per protocol
is(SQE::USM::maclen('sha1'),   12, 'sha1 maclen');
is(SQE::USM::maclen('sha256'), 24, 'sha256 maclen');
is(SQE::USM::maclen('sha512'), 48, 'sha512 maclen');
is(length SQE::USM::hmac('sha256', 'x' x 24, 'hello'), 24, 'hmac truncated to maclen');

# priv key is 16 bytes (AES-128), derived with the auth algorithm
is(length SQE::USM::priv_key('sha256', 'sqeprivpass12', $eid), 16, 'priv key is 16 bytes');

# AES-CFB128 round-trips for a non-block-aligned payload
my $key  = SQE::USM::priv_key('sha256', 'sqeprivpass12', $eid);
my $salt = pack('H*', '1122334455667788');
my $pt   = 'scopedPDU bytes not aligned to 16 !!';
my $ct   = SQE::USM::aes_cfb('e', $key, 12, 3456, $salt, $pt);
isnt($ct, $pt, 'ciphertext differs from plaintext');
is(SQE::USM::aes_cfb('d', $key, 12, 3456, $salt, $ct), $pt, 'AES-128-CFB round-trip');

done_testing;
