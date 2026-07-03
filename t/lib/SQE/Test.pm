package SQE::Test;
# ABOUTME: Shared helpers for snmp-query-engine integration tests: daemon
# ABOUTME: lifecycle, msgpack-over-TCP client, and Test2 template matching.
use strict;
use warnings;
use IO::Socket::INET;
use Data::MessagePack;
use Time::HiRes ();
use FindBin;
use File::Spec;
use Scalar::Util qw(blessed);
use Test2::Tools::Compare qw(is hash array field item etc end match);
use Exporter 'import';

use constant {
	RT_SETOPT    => 1,
	RT_GETOPT    => 2,
	RT_INFO      => 3,
	RT_GET       => 4,
	RT_GETTABLE  => 5,
	RT_DEST_INFO => 6,
	RT_REPLY     => 0x10,
	RT_ERROR     => 0x20,
};

our @EXPORT_OK = qw(spawn_daemon request_match to_check oid_cmp
	RT_SETOPT RT_GETOPT RT_INFO RT_GET RT_GETTABLE RT_DEST_INFO RT_REPLY RT_ERROR);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

sub oid_cmp {
	my @a = split /\./, $_[0];
	my @b = split /\./, $_[1];
	while (@a && @b) {
		my $c = shift(@a) <=> shift(@b);
		return $c if $c;
	}
	return @a <=> @b;
}

sub _free_port {
	# There is a TOCTOU race here: the socket is closed before the daemon
	# gets a chance to bind the same port, so something else could grab it
	# first. The connect-retry loop in spawn_daemon compensates by retrying
	# instead of assuming the daemon is up on the first attempt.
	my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
		Proto => 'tcp', Listen => 1) or die "cannot find a free port: $!";
	my $port = $s->sockport;
	$s->close;
	return $port;
}

sub spawn_daemon {
	my $engine = "$FindBin::Bin/../snmp-query-engine";
	-x $engine or die "$engine not built, run make first\n";
	my $port = _free_port();
	my $pid = fork() // die "fork: $!";
	if (!$pid) {
		# The daemon's own diagnostics are not the test's assertion channel
		# (tests assert on the msgpack replies over TCP), so discard the
		# child's stderr to keep `make test` output pristine.
		open STDERR, '>', File::Spec->devnull or exit 1;
		exec $engine, "-p$port", "-q";
		exit 1;  # unreach
	}
	my $conn;
	for (1..100) {
		$conn = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port", Proto => "tcp")
			and last;
		Time::HiRes::sleep(0.05);
	}
	unless ($conn) {
		kill 15, $pid;
		waitpid $pid, 0;
		die "cannot connect to snmp-query-engine daemon on port $port\n";
	}
	my $mp = Data::MessagePack->new->prefer_integer;
	return bless { pid => $pid, port => $port, conn => $conn, mp => $mp }, 'SQE::Test::Daemon';
}

sub to_check {
	my ($t) = @_;
	return $t if blessed($t) && $t->isa('Test2::Compare::Base');
	my $r = ref $t;
	if ($r eq 'Regexp') {
		return match $t;
	}
	if ($r eq 'HASH') {
		my %t = %$t;
		return hash { field $_ => to_check($t{$_}) for sort keys %t; etc() };
	}
	if ($r eq 'ARRAY') {
		my @t = @$t;
		return array { item to_check($_) for @t; end() };
	}
	return $t;
}

sub request_match {
	my ($d, $name, $req, $template) = @_;
	my $res = $d->request($req);
	is($res, to_check($template), $name);
	return $res;
}

package SQE::Test::Daemon;
use strict;
use warnings;
use Data::MessagePack ();

sub port { $_[0]{port} }
sub mp   { $_[0]{mp} }

sub request {
	my ($self, $d) = @_;
	$self->{conn}->syswrite($self->{mp}->pack($d));
	my $reply = "";
	$self->{conn}->sysread($reply, 65536);
	return $self->{mp}->unpack($reply);
}

sub lone_request {
	my ($self, $d) = @_;
	$self->{conn}->syswrite($self->{mp}->pack($d));
}

sub multi_request {
	my ($self, @d) = @_;
	$self->{conn}->syswrite(join '', map { $self->{mp}->pack($_) } @d);
}

sub bulk_response {
	my ($self) = @_;
	my $reply;
	$self->{conn}->sysread($reply, 65536);
	my $up = Data::MessagePack::Unpacker->new;
	my $offset = 0;
	my @r;
	while ($offset < length($reply)) {
		$offset = $up->execute($reply, $offset);
		push @r, $up->data;
		$up->reset;
		$reply = substr($reply, $offset);
		$offset = 0;
	}
	return @r;
}

sub stop {
	my ($self) = @_;
	return unless $self->{pid};
	close $self->{conn} if $self->{conn};
	kill 15, $self->{pid};
	waitpid $self->{pid}, 0;
	$self->{pid} = undef;
}

sub DESTROY {
	local ($., $@, $!, $^E, $?);
	$_[0]->stop;
}

1;
