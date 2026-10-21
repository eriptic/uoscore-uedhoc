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
cd test/
rm -rf build/; west build -b native_sim
west build -t run
```

The CI scripts in `test/ci_scripts/` (build options, Linux samples, ROM and
stack reports) can be run the same way from inside the container.

## Building for a board, flashing and debugging

```sh
cd test/
rm -rf build/; west build -b nrf9160dk/nrf9160
west flash -r jlink
```

Note: the BLE samples in `samples/zephyr_edhoc/` use IPv6 over BLE
(`CONFIG_NET_L2_BT`), which is not available in current Zephyr, so they do not
build with the Zephyr version used by this container.

J-Link and pyOCD are installed. The container mounts the host `/dev`, so a
probe visible on the host is visible in the container. On Windows/WSL forward
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

Only the Zephyr modules needed for the tests and the Nordic boards used by the
samples are fetched. To build for other boards, add the required HAL to
`name-allowlist` in [west.yml](west.yml) and rebuild the container
(**Dev Containers: Rebuild Container**).

## Tool versions

To upgrade a tool, change the version in the file listed below and rebuild the
container.

| Tool       | Version                     | Pinned in                                        |
| ---------- | --------------------------- | ------------------------------------------------ |
| Zephyr     | `main` (development branch) | `west.yml` (`revision`)                          |
| Zephyr SDK | derived                     | follows the pinned Zephyr (`zephyr/SDK_VERSION`) |
| west       | 1.5.0                       | `scripts/install_zephyr.sh`                      |
| J-Link     | V9.86a                      | `scripts/install_debuggers.sh`                   |
| pyOCD      | 0.46.0                      | `scripts/install_debuggers.sh`                   |
