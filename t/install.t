#!/usr/bin/env perl
# ABOUTME: Verifies make install places the binary and man page under
# ABOUTME: DESTDIR with the default PREFIX layout.
use strict;
use warnings;
use FindBin;
use Test2::V0;
use File::Temp ();

my $root = "$FindBin::Bin/..";
my $dir = File::Temp->newdir;
my $out = qx(make -C $root install DESTDIR=$dir 2>&1);
is($? >> 8, 0, 'make install succeeds') or diag($out);
ok(-x "$dir/usr/local/bin/snmp-query-engine", 'binary installed executable');
ok(-f "$dir/usr/local/share/man/man1/snmp-query-engine.1", 'man page installed');

done_testing;
