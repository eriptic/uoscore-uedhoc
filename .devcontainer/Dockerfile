# Use Ubuntu base image, pinned by digest for reproducible builds.
# To update: re-resolve the current ubuntu:24.04 digest and replace below.
FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

# Environment setup
ENV DEBIAN_FRONTEND=noninteractive

# Configure user (static commands for user setup)
COPY scripts/configure_user.sh /scripts/configure_user.sh
RUN chmod +x /scripts/configure_user.sh && \
    /scripts/configure_user.sh

# Switch to non-root user
USER ubuntu
WORKDIR /home/ubuntu
# Single source of truth for the Zephyr workspace location; scripts inherit this.
ENV ZEPHYR_DIR=/home/ubuntu/zephyrproject

# Install base tools and dependencies
COPY scripts/install_basic_tools.sh /scripts/install_basic_tools.sh
RUN /scripts/install_basic_tools.sh

# Copy and run Zephyr setup (uses custom manifest to limit cloned repos)
COPY west.yml /scripts/west.yml
COPY scripts/install_zephyr.sh /scripts/install_zephyr.sh
RUN /scripts/install_zephyr.sh

# Install Zephyr SDK (direct download to avoid GitHub API rate limits)
COPY scripts/install_zephyr_sdk.sh /scripts/install_zephyr_sdk.sh
RUN /scripts/install_zephyr_sdk.sh

# Install debug probe tools (J-Link, pyOCD)
COPY scripts/install_debuggers.sh /scripts/install_debuggers.sh
RUN /scripts/install_debuggers.sh

# Make west, the Zephyr environment and J-Link available in non-interactive
# shells too (e.g. CI steps run via `devcontainer exec`).
ENV VIRTUAL_ENV=${ZEPHYR_DIR}/.venv
ENV ZEPHYR_BASE=${ZEPHYR_DIR}/zephyr
ENV PATH="${VIRTUAL_ENV}/bin:/opt/SEGGER/JLink:${PATH}"

# Default shell command
CMD ["/bin/bash"]
