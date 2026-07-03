package SQE::FakeAgent;
# ABOUTME: Scriptable fake SNMP v1/v2c agent for integration tests: serves a
# ABOUTME: fixed OID tree over UDP with configurable misbehavior.
use strict;
use warnings;
use IO::Socket::INET;
use POSIX ();

sub _oid_cmp {
	my @a = split /\./, $_[0];
	my @b = split /\./, $_[1];
	while (@a && @b) {
		my $c = shift(@a) <=> shift(@b);
		return $c if $c;
	}
	return @a <=> @b;
}

sub spawn {
	my ($class, %opt) = @_;
	my $self = bless {
		community  => $opt{community} // 'public',
		tree       => [sort { _oid_cmp($a->[0], $b->[0]) } @{ $opt{tree} // [] }],
		drop_first => $opt{drop_first} // 0,
		drop_all   => $opt{drop_all} // 0,
		repeat_oid => $opt{repeat_oid},
		malformed  => $opt{malformed} // '',
		delay_ms   => $opt{delay_ms} // 0,
	}, $class;
	pipe(my $rd, my $wr) or die "pipe: $!";
	my $pid = fork() // die "fork: $!";
	if (!$pid) {
		close $rd;
		my $sock = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
			LocalPort => 0, Proto => 'udp') or POSIX::_exit(1);
		print $wr $sock->sockport, "\n";
		close $wr;
		$self->_serve($sock);
		POSIX::_exit(0);
	}
	close $wr;
	chomp(my $port = <$rd> // '');
	close $rd;
	$port or die "fake agent failed to start\n";
	$self->{pid}  = $pid;
	$self->{port} = $port;
	return $self;
}

sub port { $_[0]{port} }

sub stop {
	my ($self) = @_;
	return unless $self->{pid};
	kill 9, $self->{pid};
	waitpid $self->{pid}, 0;
	$self->{pid} = undef;
}

sub DESTROY {
	local ($., $@, $!, $^E, $?);
	$_[0]->stop;
}

sub _serve {
	my ($self, $sock) = @_;
	my $n = 0;
	while (1) {
		my $peer = $sock->recv(my $pkt, 65535);
		defined $peer or next;
		$n++;
		next if $self->{drop_all};
		next if $n <= $self->{drop_first};
		my $reply = eval { $self->_handle($pkt) };
		next unless defined $reply;
		if ($self->{malformed} eq 'truncate') {
			$reply = substr($reply, 0, int(length($reply) / 2));
		} elsif ($self->{malformed} eq 'garbage') {
			$reply = "\xde\xad\xbe\xef" x 8;
		}
		select(undef, undef, undef, $self->{delay_ms} / 1000) if $self->{delay_ms};
		$sock->send($reply, 0, $peer);
	}
}

# ---- BER encoding ----

sub _ber_len {
	my ($n) = @_;
	return chr($n) if $n < 0x80;
	my $b = '';
	while ($n) { $b = chr($n & 0xff) . $b; $n >>= 8 }
	return chr(0x80 | length $b) . $b;
}

sub _tlv {
	my ($tag, $content) = @_;
	return chr($tag) . _ber_len(length $content) . $content;
}

sub _enc_uint {   # unsigned integer-valued types (INTEGER >= 0, Counter, Gauge, TimeTicks)
	my ($tag, $n) = @_;
	my @b;
	do { unshift @b, $n & 0xff; $n >>= 8 } while ($n);
	unshift @b, 0 if $b[0] & 0x80;
	return _tlv($tag, join '', map chr, @b);
}

sub _enc_oid_content {
	my @arc = split /\./, $_[0];
	my $c = chr(40 * $arc[0] + $arc[1]);
	for my $a (@arc[2 .. $#arc]) {
		my $e = chr($a & 0x7f);
		while ($a >>= 7) { $e = chr(0x80 | ($a & 0x7f)) . $e }
		$c .= $e;
	}
	return $c;
}

sub _enc_value {
	my ($type, $v) = @_;
	return _enc_uint(0x02, $v)                  if $type eq 'int';
	return _tlv(0x04, $v)                       if $type eq 'str';
	return _tlv(0x06, _enc_oid_content($v))     if $type eq 'oid';
	return _enc_uint(0x41, $v)                  if $type eq 'counter';
	return _enc_uint(0x42, $v)                  if $type eq 'gauge';
	return _enc_uint(0x43, $v)                  if $type eq 'ticks';
	return _tlv($type, '')                      if $type =~ /^\d+$/;  # null / exceptions, by tag
	die "unknown value type $type";
}

# ---- BER decoding ----

sub _get_tlv {   # ($buf, $pos) -> ($tag, $content, $newpos)
	my ($buf, $pos) = @_;
	die "short packet\n" if $pos + 2 > length $buf;
	my $tag = ord substr($buf, $pos++, 1);
	my $len = ord substr($buf, $pos++, 1);
	if ($len & 0x80) {
		my $n = $len & 0x7f;
		die "bad length\n" if $n == 0 || $n > 4;
		die "short packet\n" if $pos + $n > length $buf;
		$len = 0;
		$len = ($len << 8) | ord substr($buf, $pos++, 1) for 1 .. $n;
	}
	die "short packet\n" if $pos + $len > length $buf;
	return ($tag, substr($buf, $pos, $len), $pos + $len);
}

sub _dec_uint {
	my $n = 0;
	$n = ($n << 8) | ord for split //, $_[0];
	return $n;
}

sub _dec_oid {
	my ($c) = @_;
	my $first = ord substr($c, 0, 1);
	my @arc = (int($first / 40), $first % 40);
	my $n = 0;
	for my $b (map ord, split //, substr($c, 1)) {
		$n = ($n << 7) | ($b & 0x7f);
		unless ($b & 0x80) { push @arc, $n; $n = 0 }
	}
	return join '.', @arc;
}

# ---- request handling ----

sub _find {
	my ($self, $oid) = @_;
	for my $e (@{ $self->{tree} }) {
		return $e if $e->[0] eq $oid;
	}
	return undef;
}

sub _next_entry {
	my ($self, $oid) = @_;
	if (defined $self->{repeat_oid} && $oid eq $self->{repeat_oid}) {
		return $self->_find($oid);   # non-increasing: "advance" to itself
	}
	for my $e (@{ $self->{tree} }) {
		return $e if _oid_cmp($e->[0], $oid) > 0;
	}
	return undef;
}

sub _handle {
	my ($self, $pkt) = @_;
	my ($tag, $msg) = _get_tlv($pkt, 0);
	die "not a sequence\n" unless $tag == 0x30;
	my $pos = 0;
	(my $t, my $ver_c, $pos) = _get_tlv($msg, $pos);
	die "bad version\n" unless $t == 0x02;
	my $version = _dec_uint($ver_c);            # 0 = v1, 1 = v2c
	($t, my $community, $pos) = _get_tlv($msg, $pos);
	die "bad community\n" unless $t == 0x04;
	return undef unless $community eq $self->{community};
	(my $pdu_tag, my $pdu, $pos) = _get_tlv($msg, $pos);

	$pos = 0;
	($t, my $reqid_c, $pos) = _get_tlv($pdu, $pos);
	(undef, my $f1_c, $pos) = _get_tlv($pdu, $pos);  # error-status | non-repeaters
	(undef, my $f2_c, $pos) = _get_tlv($pdu, $pos);  # error-index  | max-repetitions
	($t, my $vbl, $pos) = _get_tlv($pdu, $pos);
	die "bad varbind list\n" unless $t == 0x30;
	my @oids;
	my $vpos = 0;
	while ($vpos < length $vbl) {
		(my $vt, my $vb, $vpos) = _get_tlv($vbl, $vpos);
		my ($ot, $oid_c) = _get_tlv($vb, 0);
		die "bad varbind\n" unless $vt == 0x30 && $ot == 0x06;
		push @oids, _dec_oid($oid_c);
	}

	my ($errst, $erridx, @out) = (0, 0);
	if ($pdu_tag == 0xa0) {          # GET
		if ($version == 0) {         # v1: all-or-nothing
			for my $i (0 .. $#oids) {
				unless ($self->_find($oids[$i])) {
					($errst, $erridx) = (2, $i + 1);   # noSuchName
					last;
				}
			}
			if ($errst) {
				@out = map { [$_, 0x05, ''] } @oids;   # echo request varbinds
			} else {
				@out = map { $self->_find($_) } @oids;
			}
		} else {                     # v2c: per-varbind exceptions
			@out = map { $self->_find($_) // [$_, 0x80, ''] } @oids;   # noSuchObject
		}
	} elsif ($pdu_tag == 0xa1) {     # GETNEXT
		if ($version == 0) {
			for my $i (0 .. $#oids) {
				unless ($self->_next_entry($oids[$i])) {
					($errst, $erridx) = (2, $i + 1);
					last;
				}
			}
			if ($errst) {
				@out = map { [$_, 0x05, ''] } @oids;
			} else {
				@out = map { $self->_next_entry($_) } @oids;
			}
		} else {
			@out = map { $self->_next_entry($_) // [$_, 0x82, ''] } @oids;   # endOfMibView
		}
	} elsif ($pdu_tag == 0xa5) {     # GETBULK (v2c)
		my $nonrep = _dec_uint($f1_c);
		my $maxrep = _dec_uint($f2_c);
		my @cursors = @oids;
		for my $i (0 .. $nonrep - 1) {
			last if $i > $#cursors;
			my $e = $self->_next_entry($cursors[$i]);
			push @out, $e // [$cursors[$i], 0x82, ''];
		}
		my @rep = @cursors[$nonrep .. $#cursors];
		for my $round (1 .. $maxrep) {
			my $progress = 0;
			for my $j (0 .. $#rep) {
				my $e = $self->_next_entry($rep[$j]);
				if ($e) {
					push @out, $e;
					$rep[$j] = $e->[0];
					$progress = 1;
				} else {
					push @out, [$rep[$j], 0x82, ''];
				}
			}
			last unless $progress;
		}
	} else {
		die "unsupported pdu $pdu_tag\n";
	}

	my $vbl_out = join '', map {
		_tlv(0x30, _tlv(0x06, _enc_oid_content($_->[0])) . _enc_value($_->[1], $_->[2]))
	} @out;
	my $resp = _tlv(0xa2,
		_tlv(0x02, $reqid_c)
		. _enc_uint(0x02, $errst)
		. _enc_uint(0x02, $erridx)
		. _tlv(0x30, $vbl_out));
	return _tlv(0x30, _enc_uint(0x02, $version) . _tlv(0x04, $community) . $resp);
}

1;
