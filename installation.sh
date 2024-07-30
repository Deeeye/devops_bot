#!/bin/bash

set -e

# Create a temporary directory
TEMP_DIR=$(mktemp -d)
echo "Created temporary directory at $TEMP_DIR"

# Extract the wheel file from the combined installer
sed '1,/^__ARCHIVE_BELOW__/d' "$0" > "$TEMP_DIR/devops_bot.whl"
echo "Extracted wheel file to $TEMP_DIR/devops_bot.whl"

# Change to the temporary directory
cd "$TEMP_DIR" || exit 1

# Update and install necessary packages
if command -v apt-get > /dev/null; then
    echo "Using apt-get for package installation"
    sudo apt-get update -y
    sudo apt-get install -y python3 python3-venv python3-pip git
elif command -v yum > /dev/null; then
    echo "Using yum for package installation"
    sudo yum install -y python3 python3-venv python3-pip git
elif command -v dnf > /dev/null; then
    echo "Using dnf for package installation"
    sudo dnf install -y python3 python3-venv python3-pip git
else
    echo "No supported package manager found, exiting."
    exit 1
fi

# Create and activate virtual environment
echo "Creating virtual environment in $TEMP_DIR/env"
python3 -m venv env || { echo "Failed to create virtual environment"; exit 1; }
echo "Virtual environment created successfully"

# Check if the virtual environment directory exists
if [ ! -d "env" ]; then
    echo "Virtual environment directory not found"
    exit 1
fi

echo "Activating virtual environment"
source env/bin/activate || { echo "Failed to activate virtual environment"; exit 1; }
echo "Virtual environment activated successfully"

# Upgrade pip and install the wheel
echo "Upgrading pip and installing the wheel file"
pip install --upgrade pip || { echo "Failed to upgrade pip"; exit 1; }
pip install ./devops_bot.whl || { echo "Failed to install wheel file"; exit 1; }

# Deactivate the virtual environment
echo "Deactivating virtual environment"
deactivate || { echo "Failed to deactivate virtual environment"; exit 1; }

# Clean up
echo "Cleaning up temporary directory"
cd ~
rm -rf "$TEMP_DIR"

exit 0

__ARCHIVE_BELOW__



