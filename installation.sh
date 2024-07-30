#!/bin/bash

# Create a temporary directory for extraction
TEMP_DIR=$(mktemp -d)
echo "Created temporary directory at $TEMP_DIR"

# Check if the wheel file exists
WHEEL_FILE=$(ls dist/*.whl 2>/dev/null)
if [ -z "$WHEEL_FILE" ]; then
    echo "Wheel file not found in the dist/ directory. Exiting."
    exit 1
fi

# Copy the wheel file to the temporary directory
cp $WHEEL_FILE $TEMP_DIR/
echo "Copied wheel file to $TEMP_DIR"

# Set up Python virtual environment
python3 -m venv $TEMP_DIR/env
source $TEMP_DIR/env/bin/activate

# Upgrade pip and install the wheel file
pip install --upgrade pip
pip install $TEMP_DIR/*.whl

# Cleanup
deactivate
rm -rf $TEMP_DIR

echo "Installation complete. You can now use the devops_bot CLI."

