#! /usr/bin/perl
use 5.006;
use strict;
use warnings;

use Data::MessagePack;

my $mp = Data::MessagePack->new()->prefer_integer;

#print $mp->pack([0,42,{key=>"value"},["1.2.3","4.5.6"]]);
print $mp->pack(["ModeratelyLongStringLongerThan32Bytes",1,-2,{dict=>42}]);
