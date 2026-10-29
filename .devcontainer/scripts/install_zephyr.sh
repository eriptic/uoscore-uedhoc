#!/bin/bash
set -euo pipefail

# Environment variables
ZEPHYR_DIR="${ZEPHYR_DIR:-/home/ubuntu/zephyrproject}"
VIRTUAL_ENV="${ZEPHYR_DIR}/.venv"
BASHRC_FILE="${HOME}/.bashrc"

# Append a line to ~/.bashrc only if it is not already present (idempotent).
add_to_bashrc() {
    local line="$1"
    if ! grep -qF -- "${line}" "${BASHRC_FILE}" 2>/dev/null; then
        echo "${line}" >> "${BASHRC_FILE}"
    fi
}

# Pinned Python tool versions for reproducible builds.
WEST_VERSION="1.5.0"
JSONSCHEMA_VERSION="4.21.1"
NINJA_VERSION="1.13.2"
JUNIT2HTML_VERSION="31.1.4"

# Install Python virtual environment
echo "Setting up Python virtual environment..."
python3 -m venv "${VIRTUAL_ENV}"
export PATH="${VIRTUAL_ENV}/bin:$PATH"

# Configure Git to improve cloning performance
git config --global http.postBuffer 52428800
git config --global http.version HTTP/1.1

# Install west and initialize Zephyr project
echo "Installing West and initializing Zephyr project..."
pip install "west==${WEST_VERSION}" "jsonschema==${JSONSCHEMA_VERSION}" "ninja==${NINJA_VERSION}" \
	"junit2html==${JUNIT2HTML_VERSION}"
mkdir -p "${ZEPHYR_DIR}/manifest-repo"
cp /scripts/west.yml "${ZEPHYR_DIR}/manifest-repo/west.yml"
cd "${ZEPHYR_DIR}"
west init -l manifest-repo
# Retry west update to tolerate transient network drops during large clones
for attempt in 1 2 3 4 5; do
	if west -v update --fetch-opt="--progress"; then
		break
	fi
	if [ "${attempt}" -eq 5 ]; then
		echo "west update failed after ${attempt} attempts" >&2
		exit 1
	fi
	echo "west update attempt ${attempt} failed; retrying..." >&2
	sleep 5
done
west zephyr-export

# Install Python dependencies for Zephyr
echo "Installing Zephyr Python dependencies..."
west packages pip --install

# Add environment configuration to .bashrc
echo "Configuring shell environment for Zephyr OS..."
add_to_bashrc "source ${VIRTUAL_ENV}/bin/activate"
add_to_bashrc "source ${ZEPHYR_DIR}/zephyr/zephyr-env.sh"

echo "Zephyr OS installation and configuration complete."
