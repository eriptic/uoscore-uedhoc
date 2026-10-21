#!/bin/bash
set -euo pipefail

# Ensure the script is being run by a user with sudo privileges
if [ "$(id -u)" -ne 0 ] && ! sudo -n true &>/dev/null; then
    echo "This script requires sudo privileges. Please run as a user with sudo access."
    exit 1
fi

# Update package lists and install necessary tools.
# Note: we intentionally do NOT run `apt upgrade` - the base image is pinned by
# digest, so upgrading the whole image here would make builds non-reproducible.
echo "Updating package lists and installing basic tools..."
sudo apt update
sudo apt install --no-install-recommends -y \
    git cmake ninja-build gperf ccache dfu-util device-tree-compiler wget \
    openssh-client python3-dev python3-pip python3-setuptools python3-tk \
    python3-venv python3-wheel xz-utils file make gcc gdb gcc-multilib \
    g++-multilib libsdl2-dev libmagic1 tar unzip bzip2 udev usbutils curl \
    cu screen net-tools tcpdump xxd lcov python3-tabulate

# Cleanup
echo "Cleaning up..."
sudo apt clean
sudo rm -rf /var/lib/apt/lists/*

echo "Basic tools installation complete."
