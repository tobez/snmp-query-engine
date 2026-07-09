package SQE::FakeAgent;
# ABOUTME: Scriptable fake SNMP v1/v2c/v3 agent for integration tests: serves a
# ABOUTME: fixed OID tree over UDP with configurable misbehavior.
use strict;
use warnings;
use IO::Socket::INET;
use POSIX ();
use SQE::USM;

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
		omit_oid   => $opt{omit_oid},
		malformed  => $opt{malformed} // '',
		delay_ms   => $opt{delay_ms} // 0,
		v3             => $opt{v3},
		v3_never_sync  => $opt{v3_never_sync} // 0,
		v3_report      => $opt{v3_report}     // '',
		v3_reply_fault => $opt{v3_reply_fault} // '',
	}, $class;
	if (my $v = $self->{v3}) {
		my $eid = pack('H*', $v->{engine_id});
		$self->{v3set} = {
			eid        => $eid,
			username   => $v->{username},
			auth_proto => $v->{auth_proto},
			auth_kul   => SQE::USM::password_to_kul($v->{auth_proto}, $v->{auth_pass}, $eid),
			priv_key   => SQE::USM::priv_key($v->{auth_proto}, $v->{priv_pass}, $eid),
			maclen     => SQE::USM::maclen($v->{auth_proto}),
			boots      => $v->{boots} // 1,
			time       => $v->{time}  // 0,
		};
	}
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
		$self->{_last_pkt} = $pkt;
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

sub _process_pdu {
	my ($self, $version, $pdu_tag, $f1_c, $f2_c, $oids) = @_;
	my @oids = @$oids;
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
		} else {                     # v2c/v3: per-varbind exceptions
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
	} elsif ($pdu_tag == 0xa5) {     # GETBULK (v2c/v3)
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
	return ($errst, $erridx, \@out);
}

sub _handle {
	my ($self, $pkt) = @_;
	my ($tag, $msg) = _get_tlv($pkt, 0);
	die "not a sequence\n" unless $tag == 0x30;
	my $pos = 0;
	(my $t, my $ver_c, $pos) = _get_tlv($msg, $pos);
	die "bad version\n" unless $t == 0x02;
	my $version = _dec_uint($ver_c);            # 0 = v1, 1 = v2c
	return $self->_handle_v3($msg, $pos) if $version == 3;
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

	my ($errst, $erridx, $out) = $self->_process_pdu($version, $pdu_tag, $f1_c, $f2_c, \@oids);
	my @out = @$out;

	@out = grep { $_->[0] ne $self->{omit_oid} } @out
		if defined $self->{omit_oid};

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

# ---- SNMPv3 / USM handling ----

# usmStats OIDs (value is a Counter32)
my %USM_STATS = (
	not_in_time    => '1.3.6.1.6.3.15.1.1.2.0',
	wrong_digests  => '1.3.6.1.6.3.15.1.1.5.0',
	unknown_user   => '1.3.6.1.6.3.15.1.1.3.0',
	unknown_engine => '1.3.6.1.6.3.15.1.1.4.0',
);

sub _rand_salt { join '', map { chr int rand 256 } 1 .. 8 }

# Parse the v3 envelope. Returns a hashref with the decoded fields plus the byte
# offset/length of msgAuthenticationParameters within $pkt (for HMAC checking).
sub _parse_v3 {
	my ($self, $pkt) = @_;
	my (undef, $body, undef) = _get_tlv($pkt, 0);         # outer SEQUENCE
	my $base = length($pkt) - length($body);              # offset of the SEQUENCE body within $pkt
	my $pos = 0;
	(undef, undef,     $pos) = _get_tlv($body, $pos);     # version (already known == 3)
	(undef, my $gdata, $pos) = _get_tlv($body, $pos);     # msgGlobalData SEQUENCE
	(undef, my $sp, my $sp_end) = _get_tlv($body, $pos);  # msgSecurityParams OCTET STRING
	my $sp_body_off = $base + ($sp_end - length($sp));    # offset of $sp within $pkt
	$pos = $sp_end;
	(my $spd_tag, my $spd, undef) = _get_tlv($body, $pos);# scopedPduData (SEQ or OCTETSTR)

	# msgGlobalData: msgID, msgMaxSize, msgFlags, msgSecurityModel
	my $gp = 0;
	(undef, my $mid_c, $gp)   = _get_tlv($gdata, $gp);
	(undef, undef,     $gp)   = _get_tlv($gdata, $gp);    # msgMaxSize
	(undef, my $flags_c, $gp) = _get_tlv($gdata, $gp);

	# USM security params sequence
	(undef, my $usm) = _get_tlv($sp, 0);
	my $up = 0;
	(undef, my $eid,  $up) = _get_tlv($usm, $up);
	(undef, my $bo_c, $up) = _get_tlv($usm, $up);
	(undef, my $ti_c, $up) = _get_tlv($usm, $up);
	(undef, my $user, $up) = _get_tlv($usm, $up);
	my $auth_val_off_in_usm = $up + 2;                    # skip authParams tag+len (maclen<128 => 1-byte len)
	(undef, my $authp, $up) = _get_tlv($usm, $up);
	(undef, my $privp, $up) = _get_tlv($usm, $up);

	# absolute offset of authParams value inside $pkt:
	my $usm_hdr = length($sp) - length($usm);             # OCTETSTR-value contains SEQUENCE header
	my $auth_abs = $sp_body_off + $usm_hdr + $auth_val_off_in_usm;

	return {
		mid      => _dec_uint($mid_c),
		flags    => ord($flags_c),
		eid      => $eid,
		boots    => _dec_uint($bo_c),
		time     => _dec_uint($ti_c),
		user     => $user,
		authp    => $authp,
		privp    => $privp,
		auth_abs => $auth_abs,
		spd_tag  => $spd_tag,
		spd      => $spd,
	};
}

# Build an OCTET STRING TLV
sub _octet { _tlv(0x04, $_[0]) }

# Build a full v3 message. %a keys: mid, flags, boots, time, authenticated (bool),
# scoped (raw scopedPDU bytes, already encrypted or plaintext), encrypted (bool),
# privp (8-byte salt or ''), eid, username, auth_kul, auth_proto.
sub _build_v3 {
	my ($self, %a) = @_;
	my $maclen = $a{authenticated} ? SQE::USM::maclen($a{auth_proto}) : 0;

	my $usm_pre  = _octet($a{eid}) . _enc_uint(0x02, $a{boots}) . _enc_uint(0x02, $a{time})
	             . _octet($a{username});
	my $authtlv  = _octet("\x00" x $maclen);
	my $auth_hdr = length($authtlv) - $maclen;            # tag+len bytes
	my $privtlv  = _octet($a{privp} // '');
	my $usm_body = $usm_pre . $authtlv . $privtlv;
	my $auth_off = length($usm_pre) + $auth_hdr;          # within $usm_body

	my $usm_seq  = _tlv(0x30, $usm_body);
	$auth_off   += length($usm_seq) - length($usm_body);  # + SEQUENCE header
	my $secparams= _octet($usm_seq);
	$auth_off   += length($secparams) - length($usm_seq); # + OCTETSTR header

	my $gdata = _tlv(0x30,
		_enc_uint(0x02, $a{mid}) . _enc_uint(0x02, 65535)
		. _octet(chr $a{flags}) . _enc_uint(0x02, 3));
	my $ver   = _enc_uint(0x02, 3);
	my $spd   = $a{encrypted} ? _octet($a{scoped}) : $a{scoped};

	my $prefix = $ver . $gdata;
	$auth_off += length($prefix);                         # secparams follows ver+gdata
	my $body   = $prefix . $secparams . $spd;
	my $msg    = _tlv(0x30, $body);
	$auth_off += length($msg) - length($body);            # + outer SEQUENCE header

	if ($a{authenticated}) {
		my $mac = SQE::USM::hmac($a{auth_proto}, $a{auth_kul}, $msg);
		substr($msg, $auth_off, $maclen) = $mac;
	}
	return $msg;
}

# Build a scopedPDU SEQUENCE: ctxEngineID, ctxName(""), inner PDU bytes.
sub _scoped { my ($self, $eid, $pdu) = @_; return _tlv(0x30, _octet($eid) . _octet('') . $pdu) }

# Build a REPORT PDU carrying one usmStats varbind (Counter32 = 1).
sub _report_pdu {
	my ($self, $mid, $oid) = @_;
	my $vb  = _tlv(0x30, _tlv(0x06, _enc_oid_content($oid)) . _enc_uint(0x41, 1));
	return _tlv(0xa8,
		_enc_uint(0x02, $mid) . _enc_uint(0x02, 0) . _enc_uint(0x02, 0) . _tlv(0x30, $vb));
}

sub _handle_v3 {
	my ($self, $msg, undef) = @_;
	my $s = $self->{v3set} or die "v3 packet but agent not configured for v3\n";
	return undef if $self->{v3_never_sync};

	my $r = $self->_parse_v3($self->{_last_pkt});

	# username must match, else send unknown-user report (noAuth)
	if ($r->{user} ne $s->{username}) {
		return $self->_v3_report($r, 'unknown_user');
	}

	# request-side auth verification: zero the auth field, recompute, compare
	my $pkt = $self->{_last_pkt};
	my $got = substr($pkt, $r->{auth_abs}, $s->{maclen});
	substr($pkt, $r->{auth_abs}, $s->{maclen}) = "\x00" x $s->{maclen};
	my $calc = SQE::USM::hmac($s->{auth_proto}, $s->{auth_kul}, $pkt);
	return $self->_v3_report($r, 'wrong_digests') if $calc ne $got;

	# forced-report knob (e.g. always answer with a chosen report type)
	return $self->_v3_report($r, $self->{v3_report}) if $self->{v3_report};

	# time-window check: out of window -> notInTimeWindows report
	if ($r->{boots} != $s->{boots} || abs($r->{time} - $s->{time}) > 150) {
		return $self->_v3_report($r, 'not_in_time');
	}

	# in window: decrypt, process, reply
	my $scoped = $r->{spd};
	if ($r->{flags} & 0x02) {           # ENCRYPTED
		$scoped = SQE::USM::aes_cfb('d', $s->{priv_key}, $r->{boots}, $r->{time}, $r->{privp}, $r->{spd});
	}
	# scoped is now a SEQUENCE { ctxEngineID, ctxName, PDU }
	my (undef, $seq_body) = _get_tlv($scoped, 0);
	my $bp = 0;
	(undef, undef,       $bp) = _get_tlv($seq_body, $bp); # ctxEngineID
	(undef, undef,       $bp) = _get_tlv($seq_body, $bp); # ctxName
	(my $pdu_tag, my $pdu, $bp) = _get_tlv($seq_body, $bp);

	my $pp = 0;
	(undef, my $reqid_c, $pp) = _get_tlv($pdu, $pp);
	(undef, my $f1_c,    $pp) = _get_tlv($pdu, $pp);
	(undef, my $f2_c,    $pp) = _get_tlv($pdu, $pp);
	(undef, my $vbl,     $pp) = _get_tlv($pdu, $pp);
	my @oids;
	my $vp = 0;
	while ($vp < length $vbl) {
		(undef, my $vb, $vp) = _get_tlv($vbl, $vp);
		my (undef, $oid_c) = _get_tlv($vb, 0);            # varbind = SEQ { OID, value }
		push @oids, _dec_oid($oid_c);
	}

	my ($errst, $erridx, $out) = $self->_process_pdu(1, $pdu_tag, $f1_c, $f2_c, \@oids);
	@$out = grep { $_->[0] ne $self->{omit_oid} } @$out if defined $self->{omit_oid};

	my $vbl_out = join '', map {
		_tlv(0x30, _tlv(0x06, _enc_oid_content($_->[0])) . _enc_value($_->[1], $_->[2]))
	} @$out;
	my $resp_pdu = _tlv(0xa2,
		_tlv(0x02, $reqid_c) . _enc_uint(0x02, $errst) . _enc_uint(0x02, $erridx) . _tlv(0x30, $vbl_out));

	my $eid = ($self->{v3_reply_fault} eq 'engine_id') ? ($s->{eid} . "\x01") : $s->{eid};
	my $user= ($self->{v3_reply_fault} eq 'username')  ? ($s->{username} . 'X') : $s->{username};

	my $scoped_plain = $self->_scoped($eid, $resp_pdu);
	my $salt = _rand_salt();
	my $enc  = SQE::USM::aes_cfb('e', $s->{priv_key}, $s->{boots}, $s->{time}, $salt, $scoped_plain);

	my $auth_kul = $s->{auth_kul};
	$auth_kul = ($auth_kul ^ ("\x01" . "\x00" x (length($auth_kul) - 1)))
		if $self->{v3_reply_fault} eq 'bad_hmac';

	my $reply = $self->_build_v3(
		mid => $r->{mid}, flags => 0x03, boots => $s->{boots}, time => $s->{time},
		authenticated => 1, encrypted => 1, scoped => $enc, privp => $salt,
		eid => $eid, username => $user, auth_kul => $auth_kul, auth_proto => $s->{auth_proto},
	);
	return $reply;
}

# Build a noAuthNoPriv report carrying $type; carries the agent's boots/time so
# the client can sync to them.
sub _v3_report {
	my ($self, $r, $type) = @_;
	my $s = $self->{v3set};
	my $oid = $USM_STATS{$type} or die "unknown report type $type\n";
	my $scoped = $self->_scoped($s->{eid}, $self->_report_pdu($r->{mid}, $oid));
	return $self->_build_v3(
		mid => $r->{mid}, flags => 0x00, boots => $s->{boots}, time => $s->{time},
		authenticated => 0, encrypted => 0, scoped => $scoped, privp => '',
		eid => $s->{eid}, username => $s->{username},
	);
}

1;
