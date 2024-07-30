#!/bin/bash

# Create a temporary directory
TMP_DIR=$(mktemp -d)
echo "Created temporary directory at $TMP_DIR"

# Check for the wheel file in the dist directory
WHEEL_FILE=$(ls dist/*.whl)
if [[ -z "$WHEEL_FILE" ]]; then
    echo "Wheel file not found in the dist/ directory. Exiting."
    exit 1
fi

# Copy the wheel file to the temporary directory
cp "$WHEEL_FILE" "$TMP_DIR/devops_bot.whl"
cd $TMP_DIR

# Create a virtual environment
python3 -m venv env
source env/bin/activate

# Upgrade pip and install the wheel file
pip install --upgrade pip
pip install ./devops_bot.whl

# Deactivate the virtual environment
deactivate

# Cleanup
rm -rf $TMP_DIR
echo "Installation completed successfully."

