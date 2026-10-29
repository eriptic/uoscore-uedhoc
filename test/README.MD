# Tests

Zephyr ztest application for uoscore and uedhoc. The test configurations are
in [tests.yaml](tests.yaml) and are run with Twister. All commands are run
from the repository root inside the dev container.

## Run the tests

```bash
west twister -T test --integration
```

This is what CI runs. See "Examine the results" below.

Other boards:

```bash
west twister -T test -p native_sim/native/64
west twister -T test -p nrf9160dk/nrf9160 --build-only
west twister -T test -p nrf9160dk/nrf9160 --device-testing --device-serial /dev/ttyACM0
west twister -T test -p kit_pse84_ai/pse846gps2dbzc4a/m33 --device-testing --device-serial /dev/ttyACM0
```

## Examine the results

Twister writes everything to `twister-out/` in the repository root.

Failed configurations of the last run, with a command to rerun each:

```bash
west twister -T test --report-summary
```

All test cases as an HTML page:

```bash
junit2html twister-out/twister_report.xml twister-out/report.html
```

Open `twister-out/report.html` in VS Code: right-click it in the Explorer,
then **Show Preview**.

The logs of one configuration are in its directory, for example
`twister-out/native_sim_native/host_gnu/.../uoscore_uedhoc.default/`:
`build.log` (build) and `handler.log` (test output).

On a board, a crash ends `handler.log` with `ZEPHYR FATAL ERROR` and the
faulting address (`pc`). To find the function:

```bash
arm-zephyr-eabi-addr2line -f -e twister-out/<board>/.../uoscore_uedhoc.default/test/zephyr/zephyr.elf <pc>
```

`arm-zephyr-eabi-addr2line` is in `/usr/local/zephyr-sdk-*/gnu/arm-zephyr-eabi/bin/`.

## Build one configuration

For debugging, build a single configuration from `tests.yaml` into a normal
build directory:

```bash
west build -p always -b native_sim -d build/test -T test/uoscore_uedhoc.default
west build -d build/test -t run
```

## Debug output

Debug output is off. To turn it on, add `overlay-debug.conf`:

```bash
west build -p always -b native_sim -d build/test -T test/uoscore_uedhoc.default \
    -- -DEXTRA_CONF_FILE=overlay-debug.conf
west build -d build/test -t run
```

## Dependencies

The library uses Zephyr's zcbor and Mbed TLS (PSA Crypto) modules. Only
compact25519 (Ed25519, EDHOC suites 0 and 1) comes from `externals/`.
`uoscore_uedhoc.tinycrypt` builds zcbor and Mbed TLS from `externals/` too
([overlay-external-deps.conf](overlay-external-deps.conf)), because TinyCrypt
is not part of Zephyr.

## Add a test configuration

Add a scenario to `tests.yaml`. The library options are Kconfig symbols, see
[../zephyr/Kconfig](../zephyr/Kconfig).
