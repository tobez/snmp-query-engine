#! /usr/bin/perl
# ABOUTME: Runs t/test_cri under a leak detector (macOS leaks or LeakSanitizer)
# ABOUTME: to prove free_client_request_info() releases everything the cri owns.
use strict;
use warnings;
use FindBin;
use Test2::V0;

my $bin = "$FindBin::Bin/test_cri";
skip_all "$bin is not built (run make first)" unless -x $bin;

my $plain = `$bin 2>&1`;
is($? >> 8, 0, "test_cri scenario passes") or diag($plain);

my $is_asan = `nm $bin 2>/dev/null` =~ /__asan/;

if ($^O eq 'darwin' && grep { -x "$_/leaks" } split /:/, $ENV{PATH}) {
	if ($is_asan) {
		note "leaks cannot inspect ASan processes; leak check skipped";
	} else {
		my $out = `leaks --atExit -- $bin 2>&1`;
		like($out, qr/\b0 leaks for 0 total leaked bytes/, "no leaks (macOS leaks)")
			or diag($out);
	}
} elsif ($is_asan) {
	local $ENV{ASAN_OPTIONS} = "detect_leaks=1";
	my $out = `$bin 2>&1`;
	my $rc = $? >> 8;
	ok($rc == 0 && $out !~ /LeakSanitizer/, "no leaks (LeakSanitizer)")
		or diag($out);
} else {
	note "no leak detector available on this platform; leak check skipped";
}

done_testing;
