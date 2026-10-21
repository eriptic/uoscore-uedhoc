#!/bin/bash
set -euo pipefail

# Installer for debug probe tooling used with the uoscore-uedhoc samples:
#   - SEGGER J-Link (e.g. on-board probe of the nRF52840 DK / nRF9160 DK)
#   - pyOCD (CMSIS-DAP probes)

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

install_jlink
install_pyocd

echo "All debug probe tools installed successfully."
