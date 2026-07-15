# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.2.0] - 2026-07-15

### Added

- Log listening config at startup and the signal that triggered shutdown
- Coalesce repeated per-agent and per-connection log messages to prevent log floods.
- snmpv3: discover agent engine ID when engineid is omitted
- snmpv3: fail requests fast on agent engine ID mismatch

### Changed

- logs: emit machine-parseable key=value lines
- Log lines carry peer, message id, and connection details

### Fixed

- v3: crash on reply with unmatched message id
- v3: memory leaks on crypto error paths
- manual: clarify GETTABLE empty replies and errors
- daemon: survive transient accept() failures instead of exiting
- logging: escape DEL, C1 controls, and invalid UTF-8 in field values
- client input: close the connection cleanly if memory runs out
- setopt: reject malformed engineid, authkul, and privkul hex strings
- fix SNMPv3 settings memory leak on client disconnect
- ber: reject oversized length claims in decoded packets
- setopt: reject empty v3 credentials and wrong-size localized keys

### Security

- No longer log SNMPv3 credentials when a setopt request fails

## [v2.1.0] - 2026-07-04

### Added

- -d and -q flags select log verbosity
- -b flag sets client listener bind address
- graceful shutdown on SIGTERM and SIGINT
- systemd readiness and watchdog support
- make install target
- example systemd unit and FreeBSD rc.d script
- tagged releases ship prebuilt Linux binaries and a source tarball

### Changed

- log output gains timestamps and severity levels

### Fixed

- survive abrupt client disconnects (SIGPIPE)

## [v2.0.0] - 2026-07-02

### Added

- changie-managed changelog
- -v command-line flag prints the program version
- INFO: new version stat with the engine version string

### Changed

- switch to semantic versioning; program_version stat is frozen

## [v1.1.0] - 2026-07-02

### Added

- SNMPv3 HMAC-SHA-2 authentication: SHA-224, SHA-256, SHA-384, SHA-512

### Fixed

- table walks terminate when a device repeatedly returns the same or a decreasing OID (thanks to Dmitry Karasik)
- BER integers are encoded with correct signed lengths
- request ids stay within the positive 4-byte BER range
- SNMPv3 msgMaxSize is encoded with correct length
- GETBULK max-repetitions is clamped to 127

## [v1.0.1] - 2023-11-10

### Changed

- larger client command buffer, with debug output for failing SETOPT requests
- quieter logging of replies outside the SNMPv3 time window

### Fixed

- engine time is not encoded in 3 bytes, for compatibility with some devices

## [v1.0.0] - 2023-08-22

### Added

- SNMPv3 support: USM authentication (SHA-1), privacy (AES and DES), engine discovery, per-destination v3 options
- more useful logging of received packets and late replies

### Changed

- consistent code formatting rules for the project

### Fixed

- SNMP version range check
- privacy key expansion when the key is given directly instead of via a password

## [v0.7.0] - 2018-11-23

### Added

- client input accepted with both BIN and STR msgpack types (thanks to Dmitry Karasik)

### Changed

- builds with modern libmsgpack-c

### Removed

- support for libmsgpack-c older than 0.6

### Fixed

- unsigned 32-bit values that fit in 4 octets are encoded in 4 octets

## [v0.6.1] - 2014-05-23

### Fixed

- malformed SNMP responses no longer confuse reply matching

## [v0.6.0] - 2014-05-01

### Added

- DEST_INFO request for per-destination statistics

## [v0.5.0] - 2013-10-01

### Added

- protection against UDP send buffer overflows, with the udp_send_buffer_overflow statistic

## [v0.4.2] - 2013-07-29

### Fixed

- SNMP error-status in replies is taken into account

## [v0.4.1] - 2013-07-26

### Fixed

- all pending SNMP packets are received and processed before polling again

## [v0.4.0] - 2013-07-22

### Added

- global throttling across all destinations
- udp_receive_buffer_size global statistic and a larger UDP receive buffer
- program_version global statistic

## [v0.3.0] - 2012-12-14

### Added

- OIDs as returned values

### Fixed

- GETTABLE terminates when the result contains a non-increasing OID
- INTEGER32 values are treated as signed
- potential buffer overrun when decoding string OIDs
- OID comparison correctness, with tests
- packets-on-the-wire counter leak when flushing a destination
- decoding of negative BER-encoded integers

## [v0.2.0] - 2012-08-31

### Added

- per-destination and per-client option settings
- destinations are ignored for a while after repeated hard timeouts (ignore_threshold, ignore_duration)
- destination unclogging when replies stop coming
- README with acknowledgements

### Fixed

- the table OID itself is never reported as part of the table in GETTABLE
- edge cases in the destination ignore mechanism

## [v0.1.0] - 2012-05-18

### Added

- multiplexing SNMP query daemon: many clients over TCP, MessagePack-encoded requests and replies
- GET, GETTABLE, SETOPT, GETOPT, and INFO request types
- SNMP v1 and v2c support
- kqueue (FreeBSD/macOS) and epoll (Linux) event loops
- per-destination throttling, retries, timeouts, and min-interval pacing
- engine and per-connection statistics via the INFO request
- destination, connection, and request dumping for diagnostics
- value types: integers, strings, OIDs of any size, Counter32/Counter64, Gauge32, TimeTicks, IPv4 addresses
- beginnings of the manual

