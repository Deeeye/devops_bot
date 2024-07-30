#!/bin/bash

# Create a temporary directory
TMP_DIR=$(mktemp -d)
echo "Created temporary directory at $TMP_DIR"

# Extract the embedded tar.gz file (containing the wheel and install script) to the temporary directory
tail -n +50 "$0" | tar -xz -C "$TMP_DIR"
cd "$TMP_DIR"

# Create virtual environment
python3 -m venv env
source env/bin/activate

# Upgrade pip and install the wheel file
pip install --upgrade pip
pip install ./devops_bot-0.1-py3-none-any.whl

# Deactivate virtual environment
deactivate

# Cleanup
cd /
rm -rf "$TMP_DIR"
echo "Installation completed successfully."

exit 0

# The following line must be the 50th line (or adjusted to the correct line number)

