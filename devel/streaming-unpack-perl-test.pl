#! /usr/bin/perl
use 5.006;
use strict;
use warnings;

use Data::Dumper;
use Data::MessagePack;
use Data::HexDump;

my $mp = Data::MessagePack->new()->prefer_integer;
my $d = "";
$d .= $mp->pack({first=>1, string=>"The quick brown fox jumps over a fat lazy dog"});
$d .= $mp->pack({second=>1, num => 42, extras => {s => "log(log(log(x))) goes to infinity with great dignity"}});
print "TOTAL \$d: ", length($d), "\n";
my $up = Data::MessagePack::Unpacker->new;
my $n = 0;

while (length($d)) {
	my $c = substr($d, 0, 11, "");
	up($c);
}

sub up
{
	my $buf = shift;
	my $cl = length($buf);
	$n += $cl;
	#print HexDump $buf;
again:
	my $o = $up->execute($buf, 0);
	if ($o) {
		print Dumper($up->data);
		print "READY $n $o\n";
		substr($buf, 0, $o - ($n-$cl), "");
		$up->reset;
		$cl = $n = length($buf);
		#print "new n: $n\n";
		#print HexDump $buf;
		$o = 0;
		goto again if $n;
	}
}
