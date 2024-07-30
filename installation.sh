#!/bin/bash

# Update and install necessary packages
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip git

# Clone the repository
git clone https://github.com/Deeeye/devops_bot.git ~/devops_bot

# Create and activate virtual environment
python3 -m venv ~/devops_bot/env
source ~/devops_bot/env/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install wheel
pip install -r ~/devops_bot/requirements.txt
pip install ~/devops_bot/
pip install PyJWT

# Deactivate the virtual environment
deactivate

# Create systemd service file
sudo tee /etc/systemd/system/devops_bot.service > /dev/null <<EOL
[Unit]
Description=DevOps Bot Service
After=network.target

[Service]
User=$(whoami)
Group=$(whoami)
WorkingDirectory=/root/devops_bot
Environment="PATH=/root/devops_bot/env/bin"
ExecStart=/root/devops_bot/env/bin/gunicorn --config /root/devops_bot/gunicorn_config.py wsgi:app
StandardOutput=journal
StandardError=journal
SyslogIdentifier=devops_bot
[Install]
WantedBy=multi-user.target
EOL

# Reload systemd, enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable devops_bot.service
sudo systemctl start devops_bot.service

# Check if the service started successfully
if sudo systemctl is-active --quiet devops_bot.service; then
    echo "DevOps Bot Service started successfully."
else
    echo "Failed to start DevOps Bot Service. Check the journal logs for details."
    exit 1
fi

# Create a wrapper script to call dob from the virtual environment
sudo tee /usr/local/bin/dob > /dev/null <<EOL
#!/bin/bash
source $HOME/devops_bot/env/bin/activate
exec dob "\$@"
EOL

# Make the wrapper script executable
sudo chmod +x /usr/local/bin/dob

# Test the executable
if command -v dob &> /dev/null; then
    echo "dob command is available."
else
    echo "dob command is not available. Something went wrong."
    exit 1
fi

echo "Setup completed successfully."
