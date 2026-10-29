#!/bin/bash
set -euo pipefail

# Installer for debug probe tooling used with the uoscore-uedhoc samples:
#   - SEGGER J-Link (e.g. on-board probe of the nRF52840 DK / nRF9160 DK)
#   - pyOCD (CMSIS-DAP probes)
#   - Infineon OpenOCD (KitProg3 probe of the KIT_PSE84_AI, default runner)
#   - probe-rs (alternative runner for the KIT_PSE84_AI)
# The install directories are added to PATH by the Dockerfile.

ZEPHYR_DIR="${ZEPHYR_DIR:-/home/ubuntu/zephyrproject}"
VIRTUAL_ENV="${ZEPHYR_DIR}/.venv"

# ---------------------------------------------------------------------------
# Pinned tool versions for reproducible builds.
# To update a debug tool, change the value here and rebuild the dev container.
# Keep these in sync with the "Tool versions" table in .devcontainer/README.md.
# ---------------------------------------------------------------------------
JLINK_VERSION="${JLINK_VERSION:-986a}"                # SEGGER J-Link (986a => V9.86a)
JLINK_MD5="${JLINK_MD5:-b5368c629f7b401d01cc038551bd60c6}"
PYOCD_VERSION="${PYOCD_VERSION:-0.46.0}"              # pyOCD PyPI version
OPENOCD_VERSION="${OPENOCD_VERSION:-5.20.0}"          # Infineon OpenOCD release
OPENOCD_BUILD="${OPENOCD_BUILD:-5.20.0.5177}"         # Infineon OpenOCD build id
OPENOCD_SHA256="${OPENOCD_SHA256:-fbb381523284d3c9fb37afbfa43d17ebbe6d4ce2da88fe15b2aa084d41641255}"
PROBE_RS_VERSION="${PROBE_RS_VERSION:-v0.32.0}"       # probe-rs release tag
PROBE_RS_INSTALLER_SHA256="${PROBE_RS_INSTALLER_SHA256:-bfa6fd47cb5dee671cf71c939b6d5695fa3f560154c018301d0abf60b525d134}"

# Install SEGGER J-Link. Its directory is added to PATH by the Dockerfile.
install_jlink() {
    echo "Installing J-Link..."

    local jlink_version="${JLINK_VERSION}"
    local jlink_url="https://www.segger.com/downloads/jlink/JLink_Linux_V${jlink_version}_x86_64.tgz"
    local jlink_md5="${JLINK_MD5}"
    local jlink_post="accept_license_agreement=accepted&submit=Download+software"
    local jlink_install_dir="${JLINK_INSTALL_DIR:-/opt/SEGGER/JLink}"
    local jlink_archive
    jlink_archive="$(basename "${jlink_url}")"

    # Download and verify J-Link installer
    curl -sLO -d "${jlink_post}" -X POST "${jlink_url}"
    echo "${jlink_md5} ${jlink_archive}" | md5sum -c -

    # Extract and install
    sudo mkdir -p "${jlink_install_dir}"
    sudo tar -xf "${jlink_archive}" -C "${jlink_install_dir}" --strip-components=1
    rm "${jlink_archive}"

    # Allow the 'ubuntu' user to access serial/USB debug interfaces
    if id "ubuntu" &>/dev/null; then
        sudo usermod -a -G dialout ubuntu
    fi

    echo "J-Link installed to ${jlink_install_dir}"
}

# Install pyOCD into the Zephyr Python virtual environment.
install_pyocd() {
    echo "Installing pyOCD..."

    if [ ! -x "${VIRTUAL_ENV}/bin/pip" ]; then
        echo "Error: Zephyr virtual environment not found at ${VIRTUAL_ENV}." >&2
        exit 1
    fi
    "${VIRTUAL_ENV}/bin/pip" install "pyocd==${PYOCD_VERSION}"

    echo "pyOCD installation complete."
}

# Install the Infineon fork of OpenOCD. Upstream OpenOCD has no PSE84 support.
# Zephyr finds it on PATH; no `-DOPENOCD=...` is needed.
install_ifx_openocd() {
    echo "Installing Infineon OpenOCD..."

    local openocd_url="https://github.com/Infineon/openocd/releases/download/release-v${OPENOCD_VERSION}/openocd-${OPENOCD_BUILD}-linux.tar.gz"
    local openocd_archive="/tmp/openocd.tar.gz"
    local install_dir="${OPENOCD_INSTALL_DIR:-/opt/infineon/openocd}"

    curl -sSfL -o "${openocd_archive}" "${openocd_url}"
    echo "${OPENOCD_SHA256} ${openocd_archive}" | sha256sum -c -

    sudo mkdir -p "${install_dir}"
    sudo tar -xzf "${openocd_archive}" -C "${install_dir}" --strip-components=1
    rm -f "${openocd_archive}"

    # KitProg3 udev rules grant access to group plugdev. They take effect only
    # when installed on the host (see .devcontainer/README.md).
    if id "ubuntu" &>/dev/null; then
        sudo usermod -a -G plugdev ubuntu
    fi

    "${install_dir}/bin/openocd" --version
    echo "Infineon OpenOCD installed to ${install_dir}"
}

# Install probe-rs with its release installer in unmanaged mode: flat layout in
# the given directory, no shell profile changes, no self-updater.
install_probe_rs() {
    echo "Installing probe-rs..."

    local installer_url="https://github.com/probe-rs/probe-rs/releases/download/${PROBE_RS_VERSION}/probe-rs-tools-installer.sh"
    local installer="/tmp/probe-rs-tools-installer.sh"
    local install_dir="${PROBE_RS_INSTALL_DIR:-/opt/probe-rs}"

    curl --proto '=https' --tlsv1.2 -sSfL -o "${installer}" "${installer_url}"
    echo "${PROBE_RS_INSTALLER_SHA256} ${installer}" | sha256sum -c -

    sudo mkdir -p "${install_dir}"
    sudo chown "$(id -u):$(id -g)" "${install_dir}"
    PROBE_RS_TOOLS_UNMANAGED_INSTALL="${install_dir}" sh "${installer}"
    rm -f "${installer}"

    "${install_dir}/probe-rs" --version
    echo "probe-rs installed to ${install_dir}"
}

install_jlink
install_pyocd
install_ifx_openocd
install_probe_rs

echo "All debug probe tools installed successfully."
