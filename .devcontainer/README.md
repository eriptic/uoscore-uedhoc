# Zephyr Dev Container

A VS Code development container with Zephyr, the Zephyr SDK and debug probe
tools preinstalled. It is used for local development and by the GitHub CI
workflow, so both use the same toolchain.

## Requirements

- Docker
- Visual Studio Code with the **Dev Containers** extension (on Windows also the
  **WSL** extension; clone the repository inside WSL)
- `~/.ssh` on the host if you want to push via SSH from inside the container
  (it is mounted read-only; `~/.gitconfig` is mounted to reuse your git
  identity)

## Getting started

1. Clone the repository and open the folder in VS Code.
2. Click **Reopen in Container** in the notification (or run
   **Dev Containers: Reopen in Container** from the Command Palette, `F1`).
3. The first build takes a while because it downloads Zephyr, the SDK and the
   debug tools; later starts are fast. Git submodules in `externals/` are
   initialized automatically after the container is created.

## Building and running the tests

```sh
west twister -T test --integration
```

See [test/README.MD](../test/README.MD) for other boards, single
configurations and debug output. The CI scripts in `test/ci_scripts/`
(standalone library check, Linux samples, ROM and stack reports) can be run the
same way from inside the container.

## Building for a board, flashing and debugging

```sh
west build -p always -b nrf9160dk/nrf9160 -d build/test -T test/uoscore_uedhoc.default
west flash -d build/test -r jlink
```

Infineon KIT_PSE84_AI (default runner: Infineon OpenOCD; `-r probe-rs` also
works):

```sh
west build -p always -b kit_pse84_ai/pse846gps2dbzc4a/m33 -d build/pse84 -T test/uoscore_uedhoc.default
west flash -d build/pse84
```

Note: the BLE samples in `samples/zephyr_edhoc/` use IPv6 over BLE
(`CONFIG_NET_L2_BT`), which is not available in current Zephyr, so they do not
build with the Zephyr version used by this container.

J-Link, pyOCD, Infineon OpenOCD and probe-rs are installed. The container
mounts the host `/dev`, so a probe visible on the host is visible in the
container. udev rules must be installed on the host (Linux/WSL), not in the
container. For the KitProg3 probe of the KIT_PSE84_AI, run on the host, from
the [Infineon OpenOCD](https://github.com/Infineon/openocd/releases) archive:
`sudo openocd/udev_rules/install_rules.sh`. For probe-rs see
[probe-rs udev rules](https://probe.rs/docs/getting-started/probe-setup/#linux%3A-udev-rules).
On Windows/WSL forward
the probe to WSL first with [usbipd-win](https://github.com/dorssel/usbipd-win)
from a Windows terminal:

```powershell
usbipd list
usbipd bind --busid <busid>    # once, elevated
usbipd attach --wsl --busid <busid>
```

The container uses host networking, so the CoAP samples can talk to boards
connected via IPv6 over BLE (`scripts/ble_connect.sh`, run on the host).

## Adding hardware support

Only the Zephyr modules needed for the tests, the Nordic boards used by the
samples and the Infineon KIT_PSE84_AI are fetched. To build for other boards, add the required HAL to
`name-allowlist` in [west.yml](west.yml) and rebuild the container
(**Dev Containers: Rebuild Container**).

## Tool versions

To upgrade a tool, change the version in the file listed below and rebuild the
container.

| Tool             | Version                     | Pinned in                                        |
| ---------------- | --------------------------- | ------------------------------------------------ |
| Zephyr           | `main` (development branch) | `west.yml` (`revision`)                          |
| Zephyr SDK       | derived                     | follows the pinned Zephyr (`zephyr/SDK_VERSION`) |
| west             | 1.5.0                       | `scripts/install_zephyr.sh`                      |
| Ninja            | 1.13.2                      | `scripts/install_zephyr.sh`                      |
| junit2html       | 31.1.4                      | `scripts/install_zephyr.sh`                      |
| J-Link           | V9.86a                      | `scripts/install_debuggers.sh`                   |
| pyOCD            | 0.46.0                      | `scripts/install_debuggers.sh`                   |
| Infineon OpenOCD | 5.20.0 (5.20.0.5177)        | `scripts/install_debuggers.sh`                   |
| probe-rs         | 0.32.0                      | `scripts/install_debuggers.sh`                   |
