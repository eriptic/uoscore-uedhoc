# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Changes before v3.1.0 can be found in the
[git history](https://github.com/eriptic/uoscore-uedhoc/commits/v3.0.5) of the
version tags.

## [Unreleased]

### Upgrade notes

- **Build system:** the top-level `Makefile`, `makefile_config.mk` and the
  Linux sample Makefiles are removed. Build the library with CMake
  (`cmake --preset default && cmake --build --preset default`, or
  `add_subdirectory()` and link `uoscore-uedhoc::uoscore-uedhoc`). The former
  `makefile_config.mk` settings are named options; the preset
  `legacy-makefile-config` reproduces their old values. See "How to Build and
  Link" and "Additional configuration options" in the README.
- **CMake 3.28** or newer is required, the same minimum as Zephyr.
- **C standard:** the standalone CMake build compiles the library as ISO C17
  without GNU extensions (`-std=c17`), the same as Zephyr. Applications that
  link the library need at least C17. The former Makefile used `-std=c11`.
- **Zephyr module:** the module's `CMakeLists.txt`, `Kconfig` and
  `uoscore_nvm.c` are now in this repository (`zephyr/`), and `zephyr/module.yml`
  no longer uses `cmake-ext`/`kconfig-ext`. The Kconfig symbols `UOSCORE`,
  `UEDHOC`, `UOSCORE_NVM_SUPPORT`, `UOSCORE_DEBUG` and `UEDHOC_DEBUG` are
  unchanged. The copy in the Zephyr tree (`modules/uoscore-uedhoc/`) is no
  longer used by this revision and can be removed there.
- **`CONFIG_UOSCORE_NVM_SUPPORT`** still requires `CONFIG_SETTINGS` and uses
  the settings-based `nvm_write_ssn()`/`nvm_read_ssn()`, unless the new
  `CONFIG_UOSCORE_NVM_CUSTOM=y` says that the application implements them.
- **Test debug output is off by default** (about 200 instead of 8,000 lines
  per run). Use `test/overlay-debug.conf` to turn it on.
- **Test options:** `-DCOMMAND_LINE_FLAGS="..."` is replaced by Kconfig
  options, e.g. `-DCONFIG_UOSCORE_UEDHOC_VLA=y -DCONFIG_UEDHOC_MESSAGE_4=y`.
  The test configurations are Twister scenarios in `test/tests.yaml`; run them
  with `west twister -T test --integration`.
- **TinyCrypt** is an add-on to Mbed TLS (`UOSCORE_UEDHOC_TINYCRYPT`), not an
  alternative: the library needs Mbed TLS/PSA in every configuration.
- **Responder C_I output:** for an int C_I, `edhoc_responder_run_extended()`
  now returns its CBOR encoding (e.g. `0x2d` for -14, as in RFC 9528
  Appendix A.1) instead of the truncated raw value. Check code that derives
  OSCORE IDs from it.
- **Cipher suites:** the responder now rejects suites that aren't in
  `suites_r`.

### Added

- CMake build: top-level `CMakeLists.txt` with one `uoscore-uedhoc` target,
  named configuration options and `CMakePresets.json` with three presets
  (`default`, `legacy-makefile-config`, `ci`).
- Twister test scenarios in `test/tests.yaml`. CI runs them with
  `west twister -T test --integration`: eight scenarios on `native_sim` and
  `native_sim/native/64` (`uoscore_uedhoc.debug` is built only).
- `test/overlay-debug.conf`: turns on the debug output of the library and the
  tests for development, e.g.
  `west build ... -- -DEXTRA_CONF_FILE=overlay-debug.conf`.
- CI checks that the API headers `edhoc.h` and `oscore.h` are self-contained:
  a `.c` file that includes only that header must compile (CMake header set
  verification).
- `cmake/uoscore_uedhoc_sources.cmake`: the single list of library sources,
  used by the CMake and Zephyr builds; `cmake/check_source_list.cmake` checks it
  in CI.
- Zephyr Kconfig options `UOSCORE_UEDHOC_EXTERNAL_DEPS`, `UOSCORE_UEDHOC_VLA`,
  `UEDHOC_MESSAGE_4`, `UOSCORE_UEDHOC_TINYCRYPT`, `UOSCORE_UEDHOC_COMPACT25519`,
  `UOSCORE_UEDHOC_UNIT_TEST` and `UOSCORE_NVM_CUSTOM`.

### Changed

- The Zephyr tests and samples build the library through the Zephyr module
  instead of running `make` through `ExternalProject_Add`. The library and the
  test application now use the same compile definitions (previously the
  library used the `makefile_config.mk` buffer sizes and the test application
  the header defaults, and Mbed TLS was configured differently for the two).
- The Linux samples are standalone CMake projects. They no longer rename files
  in the `compact25519` and `tinycrypt` submodules.
- Dev container: Ninja 1.13.2 from PyPI replaces Ubuntu's 1.11.1, so parallel
  Twister builds share the CPUs through Twister's job server. junit2html
  (pinned) and the Live Preview extension are installed to view Twister's
  test report as HTML (see `test/README.MD`). Rebuild the container to get
  these.
- Dev container and tests: support for the Infineon KIT_PSE84_AI
  (`kit_pse84_ai/pse846gps2dbzc4a/m33`). The container fetches the
  `hal_infineon` and `mcuboot` (imgtool, signs the image) modules and installs
  Infineon OpenOCD 5.20.0 and probe-rs 0.32.0. The board is in
  `platform_allow` of `test/tests.yaml`; CI still runs on `native_sim` only.
- The Zephyr tests use Zephyr's zcbor and Mbed TLS 4 / TF-PSA-Crypto modules
  instead of `externals/`; only compact25519 is still built from
  `externals/compact25519`, now by the Zephyr module itself.
  `uoscore_uedhoc.tinycrypt` keeps building everything from `externals/`
  (`test/overlay-external-deps.conf`). The dev container fetches the
  `mbedtls`, `tf-psa-crypto`, `zcbor`, `trusted-firmware-m` and `tf-m-tests`
  modules.
- Zephyr Kconfig: `UOSCORE_UEDHOC_COMPACT25519` no longer requires
  `UOSCORE_UEDHOC_EXTERNAL_DEPS`. With Zephyr's Mbed TLS, `UEDHOC` enables
  X.509 certificate parsing (`MBEDTLS_X509_CRT_PARSE_C`, `MBEDTLS_MD_C`),
  which `src/edhoc/cert.c` needs.

### Removed

- `Makefile`, `makefile_config.mk` and the Linux sample Makefiles.
- `test/ci_scripts/test_build_options.sh`; its configurations are Twister
  scenarios now.

### Fixed

- edhoc: the responder keeps an int C_I in its CBOR encoding and rejects ints
  outside -24..23 ([#87]).
- edhoc: check return values that were ignored in some places ([#87]).
- edhoc: add length checks to the built-in X.509 parser ([#87]).
- edhoc: the responder checks that it supports the selected cipher suite
  ([#87]).
- edhoc: `src/edhoc/cert.c` builds with Mbed TLS 4 (Zephyr's current Mbed TLS)
  as well as 3.6.
- test: the initiator/responder threads of the EDHOC interaction tests had
  7500-byte stacks; with Zephyr's Mbed TLS they need up to 8336 bytes
  (measured on the KIT_PSE84_AI), which overflowed. They now have 10240 bytes
  (`STACKSIZE`, can be overridden at build time). `REPORT_STACK_USAGE` builds
  again with the current `thread_analyzer_print()` API.

## [3.1.1] - 2026-10-21

### Added

- VS Code dev container (`.devcontainer/`) with Zephyr, the Zephyr SDK and
  debug probe tools, plus Node.js/npm for release versioning ([#86]).

### Changed

- CI: build and test steps run inside the dev container ([#86]).

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

[Unreleased]: https://github.com/eriptic/uoscore-uedhoc/compare/v3.1.1...HEAD
[3.1.1]: https://github.com/eriptic/uoscore-uedhoc/compare/v3.1.0...v3.1.1
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
[#86]: https://github.com/eriptic/uoscore-uedhoc/pull/86
[#87]: https://github.com/eriptic/uoscore-uedhoc/pull/87
