import os
import shutil
import json
import requests
import boto3
import click
import psutil
import uuid
import time
import secrets
import threading
from getpass import getpass
from datetime import datetime
from tabulate import tabulate
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

cli = click.Group()

# Flask app initialization
app = Flask(__name__)

# Constants
API_BASE_URL = "https://devopsbot-testserver.online"
JENKINS_KEY_FILE = 'jenkins_key.key'
JENKINS_CREDENTIALS_BUCKET = 'jenkins-credentials.dob'
JENKINS_CREDENTIALS_FILE = 'jenkins_credentials.enc'
BASE_DIR = os.path.expanduser("~/.etc/devops-bot")
VERSION_BUCKET_NAME = "devops-bot-version-bucket"
VERSION_DIR = os.path.join(BASE_DIR, "version")
KEY_FILE = os.path.join(BASE_DIR, "key.key")
MASTER_INFO_FILE = os.path.join(BASE_DIR, "master_info.json")
AWS_CREDENTIALS_FILE = os.path.join(BASE_DIR, "aws_credentials.json")
DEVOPS_BOT_TOKEN_FILE = os.path.join(BASE_DIR, "devops_bot_token")
DOB_SCREENPLAY_FILE = os.path.join(BASE_DIR, "dob_screenplay.yaml")
VAULT_FOLDER = os.path.join(BASE_DIR, "vault")
CONFIG_FILE = os.path.join(VAULT_FOLDER, "config.json")
TOKEN_FILE = os.path.join(BASE_DIR, "token")

# Ensure necessary folders
def ensure_folder(path, mode=0o700):
    if not os.path.exists(path):
        os.makedirs(path, mode=mode, exist_ok=True)

ensure_folder(BASE_DIR)
ensure_folder(VERSION_DIR)
ensure_folder(VAULT_FOLDER)

# Utility functions
def get_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return None

def generate_token():
    return secrets.token_urlsafe(32)

def save_token(token):
    with open(TOKEN_FILE, 'w') as f:
        f.write(token)
    os.chmod(TOKEN_FILE, 0o600)

def load_token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as f:
            return f.read().strip()
    return None

def encrypt_file(filepath, key):
    fernet = Fernet(key)
    with open(filepath, "rb") as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(filepath, "wb") as encrypted_file:
        encrypted_file.write(encrypted)

def decrypt_file(filepath, key):
    fernet = Fernet(key)
    with open(filepath, "rb") as encrypted_file:
        encrypted = encrypted_file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(filepath, "wb") as decrypted_file:
        decrypted_file.write(decrypted)

def move_to_vault(file_path, key):
    ensure_folder(VAULT_FOLDER)
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return
    destination = os.path.join(VAULT_FOLDER, os.path.basename(file_path))
    shutil.move(file_path, destination)
    encrypt_file(destination, key)
    print(f"Moved and encrypted {file_path} to the vault.")

def pull_from_vault(file_name, key):
    file_path = os.path.join(VAULT_FOLDER, file_name)
    if not os.path.exists(file_path):
        print(f"File {file_name} does not exist in the vault.")
        return
    decrypt_file(file_path, key)
    shutil.move(file_path, os.getcwd())
    print(f"Decrypted and moved {file_name} to the current directory.")

def show_files():
    ensure_folder(VAULT_FOLDER)
    files = [f for f in os.listdir(VAULT_FOLDER) if f != "config.json"]
    if files:
        print("Files in the vault:")
        for file in files:
            print(f" - {file}")
    else:
        print("The vault is empty.")

# Vault commands
@click.group()
def vault():
    """Manage the vault for sensitive information."""
    pass

@vault.command(name="setup", help="Setup the vault for sensitive information.")
def setup_cmd():
    if os.path.exists(CONFIG_FILE):
        print("Vault is already set up. Please use 'vault-config' to configure the vault.")
        return

    password = getpass("Password: ")
    confirm_password = getpass("Repeat for confirmation: ")
    if password != confirm_password:
        print("Passwords do not match. Please try again.")
        return

    salt = os.urandom(16)
    key = get_key(password, salt)
    config = {"salt": urlsafe_b64encode(salt).decode('utf-8')}
    save_config(config)
    token = generate_token()
    save_token(token)
    click.echo(f"Vault has been set up. Please save this token securely: {token}")

@vault.command(name="config", help="Configure the vault with password and token.")
def config_cmd():
    if not os.path.exists(CONFIG_FILE):
        print("Vault is not set up. Please use 'vault-setup' to set up the vault first.")
        return

    password = getpass("Password: ")
    token = getpass("Token: ")
    saved_token = load_token()

    if token != saved_token:
        print("Invalid token.")
        return

    salt = urlsafe_b64decode(load_config()["salt"].encode('utf-8'))
    key = get_key(password, salt)
    click.echo("Vault configured successfully.")

@vault.command(name="move", help="Move a file to the vault and encrypt it.")
@click.argument('file_path')
def move_cmd(file_path):
    config = load_config()
    if not config:
        print("Vault is not set up.")
        return

    salt = urlsafe_b64decode(config["salt"].encode('utf-8'))
    password = getpass("Password: ")
    token = getpass("Token: ")
    saved_token = load_token()

    if token != saved_token:
        print("Invalid token.")
        return

    key = get_key(password, salt)
    move_to_vault(file_path, key)

@vault.command(name="pull", help="Pull a file from the vault and decrypt it.")
@click.argument('file_name')
def pull_cmd(file_name):
    config = load_config()
    if not config:
        print("Vault is not set up.")
        return

    salt = urlsafe_b64decode(config["salt"].encode('utf-8'))
    password = getpass("Password: ")
    token = getpass("Token: ")
    saved_token = load_token()

    if token != saved_token:
        print("Invalid token.")
        return

    key = get_key(password, salt)
    pull_from_vault(file_name, key)

@vault.command(name="show", help="Show files in the vault.")
def show_cmd():
    show_files()

@vault.command(name="encrypt", help="Encrypt a file.")
@click.argument('file_path')
def encrypt_cmd(file_path):
    config = load_config()
    if not config:
        print("Vault is not set up.")
        return

    salt = urlsafe_b64decode(config["salt"].encode('utf-8'))
    password = getpass("Password: ")
    key = get_key(password, salt)
    encrypt_file(file_path, key)
    print(f"File {file_path} has been encrypted.")

@vault.command(name="decrypt", help="Decrypt a file.")
@click.argument('file_path')
def decrypt_cmd(file_path):
    config = load_config()
    if not config:
        print("Vault is not set up.")
        return

    salt = urlsafe_b64decode(config["salt"].encode('utf-8'))
    password = getpass("Password: ")
    key = get_key(password, salt)
    decrypt_file(file_path, key)
    print(f"File {file_path} has been decrypted.")

# Jenkins-related functions
def generate_jenkins_key():
    key = Fernet.generate_key()
    with open(JENKINS_KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    click.echo("Jenkins encryption key generated and saved.")

def load_jenkins_key():
    return open(JENKINS_KEY_FILE, 'rb').read()

def encrypt_jenkins_data(data, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return encrypted

def decrypt_jenkins_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data).decode()
    return decrypted

def save_jenkins_credentials_to_s3(url, job_name, username, api_token):
    ensure_folder(BASE_DIR)
    if not os.path.exists(JENKINS_KEY_FILE):
        generate_jenkins_key()
    key = load_jenkins_key()

    credentials = {
        'jenkins_url': url,
        'job_name': job_name,
        'username': username,
        'api_token': api_token
    }

    encrypted_credentials = encrypt_jenkins_data(json.dumps(credentials), key)

    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', **credentials)
        s3.create_bucket(Bucket=JENKINS_CREDENTIALS_BUCKET)
        s3.put_object(Bucket=JENKINS_CREDENTIALS_BUCKET, Key=JENKINS_CREDENTIALS_FILE, Body=encrypted_credentials)
        click.echo(f"Jenkins credentials saved to S3 bucket {JENKINS_CREDENTIALS_BUCKET}.")
    except (NoCredentialsError, PartialCredentialsError) as e:
        click.echo(f"Error with AWS credentials: {e}")
    except ClientError as e:
        click.echo(f"Error saving credentials to S3: {e}")

@cli.command(name="configure-jenkins", help="Configure Jenkins credentials and save them to S3.")
@click.option('--jenkins_url', required=True, help="Jenkins URL")
@click.option('--job_name', required=True, help="Jenkins Job Name")
@click.option('--username', required=True, help="Jenkins Username")
@click.option('--api_token', required=True, hide_input=True, help="Jenkins API Token")
def configure_jenkins(jenkins_url, job_name, username, api_token):
    save_jenkins_credentials_to_s3(jenkins_url, job_name, username, api_token)

def load_aws_credentials():
    try:
        if os.path.exists(AWS_CREDENTIALS_FILE):
            key = load_key()
            with open(AWS_CREDENTIALS_FILE, 'rb') as cred_file:
                encrypted_credentials = cred_file.read()
            decrypted_credentials = decrypt_data(encrypted_credentials, key)
            return json.loads(decrypted_credentials)
    except FileNotFoundError:
        pass
    return None

def save_aws_credentials(access_key, secret_key, region):
    ensure_folder(BASE_DIR)
    key = load_key()
    credentials = {
        'aws_access_key_id': access_key,
        'aws_secret_access_key': secret_key,
        'region_name': region
    }
    encrypted_credentials = encrypt_data(json.dumps(credentials), key)
    with open(AWS_CREDENTIALS_FILE, 'wb') as cred_file:
        cred_file.write(encrypted_credentials)
    os.chmod(AWS_CREDENTIALS_FILE, 0o600)
    click.echo("AWS credentials encrypted and saved locally.")

@cli.command(name="configure-aws", help="Configure AWS credentials.")
@click.option('--aws_access_key_id', required=True, help="AWS Access Key ID")
@click.option('--aws_secret_access_key', required=True, help="AWS Secret Access Key")
@click.option('--region', required=True, help="AWS Region")
def configure_aws(aws_access_key_id, aws_secret_access_key, region):
    save_aws_credentials(aws_access_key_id, aws_secret_access_key, region)
    click.echo("AWS credentials configured successfully.")

# Master setup functions
def get_instance_metadata():
    """Fetch instance metadata from AWS metadata service."""
    metadata_url = "http://169.254.169.254/latest/meta-data/"
    token_url = "http://169.254.169.254/latest/api/token"

    try:
        # Fetch IMDSv2 token
        token_response = requests.put(token_url, headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
        token_response.raise_for_status()
        token = token_response.text

        headers = {"X-aws-ec2-metadata-token": token}
        endpoints = ["instance-id", "public-ipv4", "security-groups", "public-keys/0/openssh-key"]

        metadata = {}
        for endpoint in endpoints:
            response = requests.get(metadata_url + endpoint, headers=headers)
            response.raise_for_status()
            if endpoint == "public-keys/0/openssh-key":
                metadata[endpoint] = response.text.split()[2]
            else:
                metadata[endpoint] = response.text

        return metadata["instance-id"], metadata["public-ipv4"], metadata["security-groups"], metadata["public-keys/0/openssh-key"]
    except RequestException as e:
        raise Exception(f"Error fetching metadata: {e}")

def save_master_info(instance_id, public_ip, security_group, key_pair):
    ensure_folder(BASE_DIR)
    master_info = {
        'instance_id': instance_id,
        'public_ip': public_ip,
        'security_group': security_group,
        'key_pair': key_pair
    }
    with open(MASTER_INFO_FILE, 'w') as f:
        json.dump(master_info, f)
    os.chmod(MASTER_INFO_FILE, 0o600)

@cli.command(name="master-setup", help="Setup master instance information.")
def setup_master():
    """Setup master instance information."""
    try:
        instance_id, public_ip, security_group, key_pair = get_instance_metadata()
        save_master_info(instance_id, public_ip, security_group, key_pair)
        click.echo(f"Master setup complete with instance ID: {instance_id}, public IP: {public_ip}, security group: {security_group}, key pair: {key_pair}")
    except Exception as e:
        click.echo(f"Failed to setup master: {e}")

# CLI commands for general functionality
@cli.command(help="Greet the user.")
def greet():
    click.echo("Hello from DevOps Bot!")

@cli.command(help="Show version information.")
def version():
    click.echo("devops-bot, version 0.1")

@cli.command(help="Login to the DevOps Bot.")
def login():
    username = click.prompt('Enter your username')
    password = click.prompt('Enter your password', hide_input=True)
    response = requests.post(f"{API_BASE_URL}/api/login", headers={'Content-Type': 'application/json'}, json={"username": username, "password": password})
    if response.status_code == 200:
        token = response.json().get('token')
        if token:
            save_token(token)
            click.echo(f"Login successful! Your token is: {token}")
        else:
            click.echo("Failed to retrieve token.")
    else:
        click.echo("Invalid username or password")

@cli.command(name="system-monitor", help="Monitor system information.")
def system_monitor():
    """Monitor and display system information."""
    system_info = {
        "CPU Usage": psutil.cpu_percent(interval=1),
        "Memory Usage": psutil.virtual_memory().percent,
        "Disk Usage": psutil.disk_usage('/').percent,
        "Network Stats": psutil.net_io_counters(),
        "Boot Time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
    }

    click.echo("System Monitoring Information:")
    for key, value in system_info.items():
        click.echo(f"{key}: {value}")

# Flask routes
@app.route('/register_worker', methods=['POST'])
def register_worker_route():
    data = request.get_json()
    worker_id = data['worker_id']
    worker_url = data['worker_url']
    register_worker(worker_id, worker_url)
    return jsonify({'message': 'Worker registered successfully'})

def register_worker(worker_id, worker_url):
    # Implement the logic to register the worker
    pass

@app.route('/list_workers', methods=['GET'])
def list_workers_route():
    # Implement the logic to list all registered workers
    pass

# Command to start the master server
@cli.command(help="Start the master server.")
@click.option('--host', default='0.0.0.0', help='Host to bind the server')
@click.option('--port', default=5001, help='Port to bind the server')
def start_master(host, port):
    app.run(host=host, port=port)

# Adding vault commands to main cli
cli.add_command(vault)

if __name__ == '__main__':
    cli.add_command(setup_master)
    cli.add_command(greet)
    cli.add_command(version)
    cli.add_command(login)
    cli.add_command(system_monitor)
    cli.add_command(configure_aws)
    cli.add_command(configure_jenkins)
    cli.add_command(start_master)

    cli()
    app.run(debug=True)
