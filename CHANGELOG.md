# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Changes before v3.1.0 can be found in the
[git history](https://github.com/eriptic/uoscore-uedhoc/commits/v3.0.5) of the
version tags.

## [Unreleased]

### Added

- VS Code dev container (`.devcontainer/`) with Zephyr, the Zephyr SDK and
  debug probe tools.

### Changed

- CI: build and test steps run inside the dev container.

## [3.1.0] - 2026-10-21

### Upgrade notes

- **Warnings are errors:** the Makefiles and the sample `prj.conf` files now
  build with `-Wall -Werror` / `CONFIG_COMPILER_WARNINGS_AS_ERRORS=y`.
- **`SUITES_I_SIZE` defaults to 2**, which uses slightly more RAM. Set it back
  to `1` in `makefile_config.mk` if you only need one suite.
- **On-the-wire changes:** `kid` and `C_R` are encoded as in RFC 9528. The
  `{ 4 : int }` form of earlier drafts is still accepted on receipt. Retest
  interoperability with peers running older uEDHOC versions.
- **Zephyr:** use `native_sim` instead of `native_posix` and the board name
  `nrf9160dk/nrf9160`.

### Added

- edhoc: a responder accepts `SUITES_I = [6, 2]` as in RFC 9529 ([#85]).
- crypto: `crypto_p256_uncompress_point()` to parse compressed EC points
  ([#75]).
- samples: IPv6 zone identifiers (`%iface`) for link-local addresses ([#73]).
- samples: CoAP Content-Format `application/edhoc+cbor-seq` for EDHOC
  messages ([#72]).
- tests: RFC 9529 trace 2 tests, an empty `C_R` trace and `kid` encoding unit
  tests ([#85]); `coap2oscore` tests for two-byte option deltas/lengths
  ([#70]).
- CI: build all Linux samples ([#74]).

### Changed

- edhoc: `kid` in `ID_CRED_x` is encoded as in RFC 9528 ([#85]).
- build: `SUITES_I_SIZE` defaults to `2` ([#85]).
- build: compile with `-Wall -Werror`; `-Wpedantic` was removed because it
  conflicts with picolibc ([#77]).
- crypto: legacy Mbed TLS bignum/PK APIs and headers are no longer used, so
  the library is ready for TF-PSA-Crypto / Mbed TLS 4.x ([#75], [#79]).
- cbor: the generated CBOR functions no longer take `const` input pointers
  ([#77]).
- deps: Mbed TLS 3.6.5 (LTS), zcbor 0.9.1, compact25519 v1.1.0 and the latest
  cantcoap ([#72], [#75], [#77]).
- CI: `native_sim` replaces `native_posix`, updated Zephyr installation and
  GitHub Actions; deploy only on `main` ([#71], [#76]).

### Removed

- edhoc: internal helper `c_r_is_raw_int()` ([#85]).

### Fixed

- edhoc: `C_R` in `context_2` is encoded as in `message_2`, so MAC_2 matches
  other implementations ([#85]).
- edhoc: an empty `C_R` is kept in `context_2` instead of failing with
  `mac_authentication_failed` ([#82], [#85]).
- edhoc: left-pad short ECDSA `r`/`s` integers when verifying certificate
  signatures ([#83]).
- oscore: handle CoAP options with two-byte option deltas/lengths in
  `inner_outer_option_split()` ([#70]).
- oscore: treat the EDHOC option (21) as Class U ([#78]).
- samples: abort on an invalid IPv6 address ([#73]).
- samples: fix linker errors in the Linux OSCORE server ([#74]).
- CI: fix `No module named jsonschema` ([#84]).

[Unreleased]: https://github.com/eriptic/uoscore-uedhoc/compare/v3.1.0...HEAD
[3.1.0]: https://github.com/eriptic/uoscore-uedhoc/compare/v3.0.5...v3.1.0
[#70]: https://github.com/eriptic/uoscore-uedhoc/pull/70
[#71]: https://github.com/eriptic/uoscore-uedhoc/pull/71
[#72]: https://github.com/eriptic/uoscore-uedhoc/pull/72
[#73]: https://github.com/eriptic/uoscore-uedhoc/pull/73
[#74]: https://github.com/eriptic/uoscore-uedhoc/pull/74
[#75]: https://github.com/eriptic/uoscore-uedhoc/pull/75
[#76]: https://github.com/eriptic/uoscore-uedhoc/pull/76
[#77]: https://github.com/eriptic/uoscore-uedhoc/pull/77
[#78]: https://github.com/eriptic/uoscore-uedhoc/pull/78
[#79]: https://github.com/eriptic/uoscore-uedhoc/pull/79
[#82]: https://github.com/eriptic/uoscore-uedhoc/issues/82
[#83]: https://github.com/eriptic/uoscore-uedhoc/pull/83
[#84]: https://github.com/eriptic/uoscore-uedhoc/pull/84
[#85]: https://github.com/eriptic/uoscore-uedhoc/pull/85
