#!/bin/bash
set -euo pipefail

# Read SDK version from Zephyr source tree
ZEPHYR_DIR="${ZEPHYR_DIR:-/home/ubuntu/zephyrproject}"
SDK_VERSION=$(cat "${ZEPHYR_DIR}/zephyr/SDK_VERSION")
SDK_INSTALL_DIR="/usr/local"

SDK_URL="https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v${SDK_VERSION}/zephyr-sdk-${SDK_VERSION}_linux-x86_64_minimal.tar.xz"
TOOLCHAIN_URL="https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v${SDK_VERSION}/toolchain_gnu_linux-x86_64_arm-zephyr-eabi.tar.xz"

# Download and extract minimal SDK
echo "Downloading Zephyr SDK ${SDK_VERSION} from ${SDK_URL}..."
wget -q -O /tmp/zephyr-sdk.tar.xz "${SDK_URL}" || { echo "ERROR: Failed to download SDK ${SDK_VERSION}. Check if the release exists at ${SDK_URL}"; exit 1; }
sudo mkdir -p "${SDK_INSTALL_DIR}"
sudo tar -xf /tmp/zephyr-sdk.tar.xz -C "${SDK_INSTALL_DIR}"

# Download and extract arm-zephyr-eabi toolchain
echo "Downloading arm-zephyr-eabi toolchain from ${TOOLCHAIN_URL}..."
wget -q -O /tmp/toolchain.tar.xz "${TOOLCHAIN_URL}" || { echo "ERROR: Failed to download toolchain. Check if the file exists at ${TOOLCHAIN_URL}"; exit 1; }
sudo tar -xf /tmp/toolchain.tar.xz -C "${SDK_INSTALL_DIR}/zephyr-sdk-${SDK_VERSION}"
rm -f /tmp/zephyr-sdk.tar.xz /tmp/toolchain.tar.xz

# Fix ownership so setup.sh can create subdirectories (e.g. gnu/)
sudo chown -R "$(id -u):$(id -g)" "${SDK_INSTALL_DIR}/zephyr-sdk-${SDK_VERSION}"

# Run SDK setup
echo "Running SDK setup..."
"${SDK_INSTALL_DIR}/zephyr-sdk-${SDK_VERSION}/setup.sh" -t arm-zephyr-eabi -c


