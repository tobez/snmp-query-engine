# Installing snmp-query-engine

This document covers building `snmp-query-engine` from source, installing it
with `make install`, and running it under a service supervisor. It assumes
familiarity with basic Unix system administration.

## 1. Building from source

`snmp-query-engine` needs a C compiler, `libmsgpack`, `libJudy`, and
`libcrypto` (from OpenSSL). Perl and two CPAN modules are needed to run the
test suite, but not to build or run the daemon itself.

On Ubuntu/Debian:

```sh
apt-get install libmsgpack-dev libjudy-dev libssl-dev
```

Some newer Debian/Ubuntu releases renamed the msgpack package to
`libmsgpack-c-dev`; use whichever your release provides.

On FreeBSD:

```sh
pkg install msgpack judy openssl
```

On macOS (Homebrew):

```sh
brew install msgpack judy openssl@3
```

Then build:

```sh
make
```

and run the test suite:

```sh
make test
```

The test suite runs the C unit tests directly and the Perl integration tests
via `prove`. The Perl tests need `Data::MessagePack` and `Test2::Suite` from
CPAN:

```sh
cpan Data::MessagePack Test2::Suite
```

No local `snmpd` is required for `make test`; a scriptable fake SNMP agent
stands in for one. See `README.markdown` for how to additionally run the
suite against a real SNMP agent.

## 2. Installing

### Prebuilt binaries

Tagged releases publish prebuilt Linux binaries as GitHub release assets,
alongside a source tarball. No compiler or dependencies are needed to use
these.

Each release ships `snmp-query-engine-X.Y.Z-linux-x86_64` and
`snmp-query-engine-X.Y.Z-linux-arm64`, a `snmp-query-engine-X.Y.Z.tar.gz`
source tarball, and a `SHA256SUMS` file covering all of them. The binaries
statically link `msgpack`, `Judy`, and OpenSSL's `libcrypto`; glibc is linked
dynamically, so the target system needs a glibc no older than Ubuntu 22.04's.

Verify a downloaded binary against the published checksums before running
it:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

### From a source build

```sh
make install
```

installs the binary to `$PREFIX/bin/snmp-query-engine` and the man page to
`$PREFIX/share/man/man1/snmp-query-engine.1`. `PREFIX` defaults to
`/usr/local`. Override it, or the more specific `BINDIR`/`MANDIR`, as needed:

```sh
make install PREFIX=/opt/snmp-query-engine
```

Packagers can stage the install under a temporary root with `DESTDIR`, which
is prepended to `BINDIR`/`MANDIR` without affecting the paths baked into the
binary:

```sh
make install DESTDIR=/tmp/stage PREFIX=/usr
```

`contrib/systemd/snmp-query-engine.service` and `contrib/rc.d/snmp_query_engine`
are not installed by `make install`; copy them into place as shown below.

## 3. Running under systemd

Copy the example unit into a path systemd searches for vendor-supplied units
(systemd 240 and later look here by default):

```sh
cp contrib/systemd/snmp-query-engine.service /usr/local/lib/systemd/system/
systemctl daemon-reload
systemctl enable --now snmp-query-engine
```

The unit runs `snmp-query-engine` directly (no forking) and expects the
binary at `/usr/local/bin/snmp-query-engine` — the default `make install`
location. If you installed to a different `PREFIX`, adjust `ExecStart` in a
drop-in rather than editing the shipped file in place.

Command-line flags are supplied via `/etc/default/snmp-query-engine`, which
the unit reads through `EnvironmentFile=-/etc/default/snmp-query-engine` (the
leading `-` means the file is optional). Set `SQE_OPTS` to whatever flags you
want passed on `ExecStart`:

```sh
SQE_OPTS=-q
```

Logs go to the systemd journal (stdout/stderr are captured automatically);
view them with:

```sh
journalctl -u snmp-query-engine
```

Reading the journal as a non-root user may require membership in the
`systemd-journal` group (or `adm` on some distributions).

The unit is `Type=notify` with `WatchdogSec=30`: the daemon signals readiness
to systemd only once its sockets are open, so `systemctl start` doesn't
return "active" until the daemon can actually accept connections, and
`Restart=always` combined with the watchdog ping restarts the daemon if it
stops responding. `DynamicUser=yes` runs the daemon under a transient,
unprivileged, per-invocation user, since the daemon writes no files and needs
no persistent identity. If you need a stable, fixed user instead (for
example to match firewall rules keyed on UID), override it in a drop-in:

```sh
systemctl edit snmp-query-engine
```

```ini
[Service]
DynamicUser=no
User=snmp-query-engine
Group=snmp-query-engine
```

## 4. Running under FreeBSD rc.d

Copy the example script into the local rc.d directory and mark it
executable:

```sh
cp contrib/rc.d/snmp_query_engine /usr/local/etc/rc.d/
chmod +x /usr/local/etc/rc.d/snmp_query_engine
```

Enable the service and configure it via `rc.conf` (`sysrc` edits `rc.conf`
for you):

```sh
sysrc snmp_query_engine_enable=YES
sysrc snmp_query_engine_args="-q"
```

Note the variable name: `snmp_query_engine_args`, not
`snmp_query_engine_flags`. The script wraps `snmp-query-engine` in
`daemon(8)`, and `rc.subr` reserves `_flags` for arguments to the wrapped
`command` — which here is `daemon(8)` itself, not `snmp-query-engine`.
`snmp_query_engine_args` is the script's own variable for the daemon's own
flags.

By default the script runs the daemon as user `nobody`
(`snmp_query_engine_user`). A dedicated unprivileged user is recommended over
the default:

```sh
pw useradd snmp-query-engine -c "snmp-query-engine daemon" -d /nonexistent -s /usr/sbin/nologin
sysrc snmp_query_engine_user=snmp-query-engine
```

`daemon(8)` supervises the process (restarting it if it exits), writes a
pidfile, and redirects its stderr to syslog under the `daemon` facility with
tag `snmp-query-engine`, so no `newsyslog` configuration is required beyond
whatever your system already does for the `daemon` facility.

Start it:

```sh
service snmp_query_engine start
```

## 5. Running under any other supervisor

`snmp-query-engine` is a plain foreground process that logs to stderr and
exits cleanly on `SIGTERM` or `SIGINT`, so it fits any process supervisor
without special support. For example, under runit:

```sh
#!/bin/sh
exec snmp-query-engine -q 2>&1
```

or under supervisord:

```ini
[program:snmp-query-engine]
command=/usr/local/bin/snmp-query-engine -q
autorestart=true
stopsignal=TERM
```

## 6. Upgrading

Build or download the new binary, replace the installed one, and restart the
service (`systemctl restart snmp-query-engine`, `service snmp_query_engine
restart`, or your supervisor's equivalent). There is no on-disk state or
schema to migrate.

To confirm which version is running, either ask the binary directly:

```sh
snmp-query-engine -v
```

or query a running daemon over its client protocol: an `info` request's
reply includes a `version` field alongside its usual statistics.
