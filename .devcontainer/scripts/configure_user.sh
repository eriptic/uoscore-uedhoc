#!/bin/bash
set -euo pipefail

# Define variables
USERNAME=ubuntu

apt update && apt install --no-install-recommends -y sudo

# Check if the user already exists
if id "${USERNAME}" &>/dev/null; then
    echo "User '${USERNAME}' already exists. Skipping user creation."
else
    # Create the user if it does not exist
    echo "Creating user '${USERNAME}' and configuring permissions..."
    useradd -ms /bin/bash "${USERNAME}"
fi

usermod -aG sudo "${USERNAME}"
echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME}
chmod 0440 /etc/sudoers.d/${USERNAME}

# Setup SSH directory
echo "Setting up SSH directory for '${USERNAME}'..."
mkdir -p /home/${USERNAME}/.ssh
chmod 700 /home/${USERNAME}/.ssh
chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}/.ssh

echo "User configuration complete."
