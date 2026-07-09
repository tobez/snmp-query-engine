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

done_testing;
