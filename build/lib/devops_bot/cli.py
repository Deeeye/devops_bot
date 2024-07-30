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
import yaml
from tqdm import tqdm



cli = click.Group()

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
ALERT_CONFIG_FILE = os.path.join(BASE_DIR, "alert_config.json")


# Flask app initialization
app = Flask(__name__)

# Ensure necessary folders
def ensure_folder(path, mode=0o700):
    if not os.path.exists(path):
        os.makedirs(path, mode=mode, exist_ok=True)


def load_key():
    if not os.path.exists(KEY_FILE):
        click.echo("Encryption key not found. Please configure the vault first.")
        raise FileNotFoundError("Encryption key not found.")
    return open(KEY_FILE, 'rb').read()

# Generate encryption key
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    click.echo("Encryption key generated and saved.")


def load_aws_credentials():
    if os.path.exists(AWS_CREDENTIALS_FILE):
        key = load_key()
        with open(AWS_CREDENTIALS_FILE, 'rb') as cred_file:
            encrypted_credentials = cred_file.read()
        decrypted_credentials = decrypt_data(encrypted_credentials, key)
        return json.loads(decrypted_credentials)
    else:
        click.echo("AWS credentials not found. Please provide them.")
        access_key = click.prompt('AWS Access Key ID')
        secret_key = click.prompt('AWS Secret Access Key')
        region = click.prompt('AWS Region')
        save_aws_credentials(access_key, secret_key, region)
        return load_aws_credentials()

@cli.command(name="init", help="Initialize the DevOps Bot working directory.")
def init():
    ensure_folder(BASE_DIR)
    click.echo(f"Working directory initialized at {BASE_DIR}")


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
        if credentials:
            s3 = boto3.client('s3', **credentials)
            s3.create_bucket(Bucket=JENKINS_CREDENTIALS_BUCKET)
            s3.put_object(Bucket=JENKINS_CREDENTIALS_BUCKET, Key=JENKINS_CREDENTIALS_FILE, Body=encrypted_credentials)
            click.echo(f"Jenkins credentials saved to S3 bucket {JENKINS_CREDENTIALS_BUCKET}.")
        else:
            click.echo("AWS credentials not found. Please configure them first.")
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


def monitor_system():
    cpu_times = psutil.cpu_times()
    virtual_memory = psutil.virtual_memory()
    swap_memory = psutil.swap_memory()
    disk_usage = psutil.disk_usage('/')
    network_stats = psutil.net_io_counters()
    boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")

    system_info = [
        ["CPU Usage (%)", psutil.cpu_percent(interval=1)],
        ["CPU User Time (s)", cpu_times.user],
        ["CPU System Time (s)", cpu_times.system],
        ["CPU Idle Time (s)", cpu_times.idle],
        ["Memory Usage (%)", virtual_memory.percent],
        ["Total Memory (GB)", virtual_memory.total / (1024 ** 3)],
        ["Available Memory (GB)", virtual_memory.available / (1024 ** 3)],
        ["Used Memory (GB)", virtual_memory.used / (1024 ** 3)],
        ["Swap Memory Usage (%)", swap_memory.percent],
        ["Total Swap Memory (GB)", swap_memory.total / (1024 ** 3)],
        ["Used Swap Memory (GB)", swap_memory.used / (1024 ** 3)],
        ["Disk Usage (%)", disk_usage.percent],
        ["Total Disk Space (GB)", disk_usage.total / (1024 ** 3)],
        ["Used Disk Space (GB)", disk_usage.used / (1024 ** 3)],
        ["Free Disk Space (GB)", disk_usage.free / (1024 ** 3)],
        ["Network Bytes Sent (MB)", network_stats.bytes_sent / (1024 ** 2)],
        ["Network Bytes Received (MB)", network_stats.bytes_recv / (1024 ** 2)],
        ["Network Packets Sent", network_stats.packets_sent],
        ["Network Packets Received", network_stats.packets_recv],
        ["Boot Time", boot_time]
    ]

    return system_info

def display_system_info(system_info):
    click.echo(tabulate(system_info, headers=["Metric", "Value"], tablefmt="grid"))

def check_for_threats(system_info):
    # Basic threat detection logic
    alerts = []
    if system_info[0][1] > 90:  # CPU Usage
        alerts.append("High CPU usage detected!")
    if system_info[4][1] > 90:  # Memory Usage
        alerts.append("High memory usage detected!")
    if system_info[11][1] > 90:  # Disk Usage
        alerts.append("High disk usage detected!")
    return alerts

@cli.command(name="system-monitor", help="Monitor and display system information.")
def system_monitor():
    """Monitor and display system information."""
    system_info = monitor_system()
    display_system_info(system_info)

    alerts = check_for_threats(system_info)
    if alerts:
        click.echo("\nAlerts:")
        for alert in alerts:
            click.echo(f" - {alert}")

    # Check if user wants to save logs
    if click.confirm("Do you want to save the logs?", default=True):
        config = load_config(CONFIG_FILE)
        if not config:
            storage_option = click.prompt("Enter 'local' to save locally or 's3' to save to S3", type=str)
            if storage_option == 's3':
                bucket_name = click.prompt("Enter the S3 bucket name", type=str)
                region_name = click.prompt("Enter the S3 region", type=str)
                config = {'storage': 's3', 'bucket_name': bucket_name, 'region_name': region_name}
            else:
                config = {'storage': 'local'}
            save_config(config, CONFIG_FILE)
        save_logs(system_info, config)

    # Check if user wants to enable alerts
    if click.confirm("Do you want to set up alerts?", default=False):
        alert_config = load_config(ALERT_CONFIG_FILE)
        if not alert_config:
            alert_option = click.prompt("Enter 'email' for email alerts or 'sms' for SMS alerts", type=str)
            if alert_option == 'email':
                email_address = click.prompt("Enter your email address", type=str)
                alert_config = {'alert': 'email', 'email_address': email_address}
            else:
                phone_number = click.prompt("Enter your phone number", type=str)
                alert_config = {'alert': 'sms', 'phone_number': phone_number}
            save_config(alert_config, ALERT_CONFIG_FILE)
        setup_alerts(alerts, alert_config)

def save_logs(system_info, config):
    if config['storage'] == 's3':
        upload_to_s3(system_info, config['bucket_name'], config['region_name'])
    else:
        ensure_folder(os.path.dirname(LOG_FILE))
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(system_info) + '\n')
        click.echo(f"Logs saved locally at {LOG_FILE}")

def upload_to_s3(system_info, bucket_name, region_name):
    try:
        s3 = boto3.client('s3', region_name=region_name)
        log_data = json.dumps(system_info)
        log_file_name = f"system_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        s3.put_object(Bucket=bucket_name, Key=log_file_name, Body=log_data)
        click.echo(f"Logs uploaded to S3 bucket '{bucket_name}' as '{log_file_name}'")
    except (NoCredentialsError, PartialCredentialsError, ClientError) as e:
        click.echo(f"Error uploading logs to S3: {e}")

def setup_alerts(alerts, alert_config):
    if alert_config['alert'] == 'email':
        send_email_alert(alerts, alert_config['email_address'])
    else:
        send_sms_alert(alerts, alert_config['phone_number'])

def send_email_alert(alerts, email_address):
    # Placeholder for actual email alerting logic
    click.echo(f"Email alert sent to {email_address} with alerts: {alerts}")

def send_sms_alert(alerts, phone_number):
    # Placeholder for actual SMS alerting logic
    click.echo(f"SMS alert sent to {phone_number} with alerts: {alerts}")



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

# Additional commands for various functionalities

@cli.command(help="Generate configuration files.")
@click.argument('resource_type')
@click.argument('manifest_type', required=False)
@click.option('--params', type=str, help="Parameters for the resource, in key=value format, separated by spaces.")
def create(resource_type, manifest_type, params):
    """Generate configuration files."""
    token = load_token()
    if not token:
        click.echo("No token found. Please log in first.")
        return

    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    data = {}

    if params:
        for param in params.split():
            key, value = param.split('=')
            data[key] = value

    response = requests.post(f"{API_BASE_URL}/generate/{resource_type}/{manifest_type}", headers=headers, json=data)

    if response.status_code == 200:
        response_data = response.json()
        if 'data' in response_data:
            yaml_content = response_data['data']
            with open(f"{resource_type}_{manifest_type}.yaml", "w") as f:
                f.write(yaml_content)
            click.echo(f"{resource_type}_{manifest_type}.yaml file has been generated and saved.")
        else:
            click.echo("Unexpected response format.")
    else:
        click.echo("Failed to generate file.")
        click.echo(response.json().get('message'))

@cli.command(name="delete-ec2", help="Delete EC2 instances using instance IDs or a version ID.")
@click.argument('ids', nargs=-1)
@click.option('--version-id', help="Version ID to delete instances from")
def delete_ec2(ids, version_id):
    instance_ids = list(ids)

    if version_id:
        version_info = load_version_info(version_id)
        if not version_info:
            click.echo("No version information found.")
            return
        instance_ids.extend(instance['InstanceId'] for instance in version_info['content'])

    if not instance_ids:
        click.echo("No instance IDs provided.")
        return

    table_data = [
        [click.style("-", fg="red"), "Instance ID", instance_id] for instance_id in instance_ids
    ]
    click.echo(click.style("\nStaging area: Deleting EC2 instance(s) with IDs:", fg="red"))
    click.echo(tabulate(table_data, headers=["", "Attribute", "Value"], tablefmt="grid"))

    if click.confirm(click.style("Do you want to proceed with deleting the instance(s)?", fg="red"), default=False):
        comment = click.prompt(click.style("Enter a comment for this version", fg="red"))
        version_id = str(uuid.uuid4())  # Generate a unique version ID

        try:
            terminated_instances = delete_ec2_instances(instance_ids)
            if terminated_instances is None:
                raise Exception("Instance deletion failed. Aborting operation.")

            click.echo(click.style("Instances deleted successfully.", fg="green"))
            for idx, instance in enumerate(terminated_instances):
                click.echo(click.style(f"Instance {idx+1}: ID = {instance['InstanceId']} - {instance['CurrentState']['Name']}", fg="green"))

            version_content = [{'InstanceId': instance['InstanceId'], 'CurrentState': instance['CurrentState']} for instance in terminated_instances]

            if check_bucket_exists(VERSION_BUCKET_NAME):
                save_version_info_to_bucket(version_id, comment, version_content)
            else:
                if click.confirm("Do you want to save the version information in a bucket?", default=False):
                    create_version_bucket()
                    save_version_info_to_bucket(version_id, comment, version_content)
                else:
                    save_version_info_locally(version_id, comment, version_content)
        except Exception as e:
            click.echo(click.style(f"Failed to delete instances: {e}", fg="red"))
    else:
        click.echo(click.style("Instance deletion aborted.", fg="yellow"))

def delete_ec2_instances(instance_ids):
    credentials = load_aws_credentials()
    if not credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return None

    ec2 = boto3.client('ec2', **credentials)
    try:
        response = ec2.terminate_instances(InstanceIds=instance_ids)
        return response['TerminatingInstances']
    except ClientError as e:
        click.echo(click.style(f"Failed to delete instances: {e}", fg="red"))
        return None

def save_version_info_locally(version_id, comment, content):
    ensure_folder(VERSION_DIR)
    key = load_key()
    version_info = {
        'version_id': version_id,
        'comment': comment,
        'content': content
    }
    encrypted_version_info = encrypt_data(json.dumps(version_info), key)
    with open(os.path.join(VERSION_DIR, f"{version_id}.enc"), 'wb') as version_file:
        version_file.write(encrypted_version_info)
    click.echo(f"Version information saved locally with ID {version_id}.")

def save_version_info_to_bucket(version_id, comment, content):
    key = load_key()
    credentials = load_aws_credentials()
    if not credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return None

    version_info = {
        'version_id': version_id,
        'comment': comment,
        'content': [serialize_instance_info(instance) for instance in content]
    }
    encrypted_version_info = encrypt_data(json.dumps(version_info), key)

    s3 = boto3.client('s3', **credentials)
    try:
        s3.put_object(Bucket=VERSION_BUCKET_NAME, Key=f"{version_id}.enc", Body=encrypted_version_info)
        click.echo(f"Version information saved in S3 bucket with ID {version_id}.")
    except ClientError as e:
        click.echo(click.style(f"Failed to save version information to bucket: {e}", fg="red"))

def create_ec2_instances(instance_type, ami_id, key_name, security_group, count, tags, user_data=None):
    credentials = load_aws_credentials()
    if not credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return None

    ec2 = boto3.client('ec2', **credentials)
    try:
        instances = ec2.run_instances(
            InstanceType=instance_type,
            ImageId=ami_id,
            KeyName=key_name,
            SecurityGroupIds=[security_group],
            MinCount=count,
            MaxCount=count,
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [{'Key': key, 'Value': value} for key, value in tags.items()]
                }
            ],
            UserData=user_data
        )
        return instances['Instances']
    except ClientError as e:
        click.echo(click.style(f"Failed to create instances: {e}", fg="red"))
        return None

@cli.command(name="create-ec2", help="Create EC2 instances with specified options.")
@click.option('--instance-type', required=True, help="EC2 instance type")
@click.option('--ami-id', required=True, help="AMI ID")
@click.option('--key-name', required=True, help="Key pair name")
@click.option('--security-group', required=True, help="Security group ID")
@click.option('--count', default=1, help="Number of instances to create")
@click.option('--tags', multiple=True, type=(str, str), help="Tags for the instance in key=value format", required=False)
def create_ec2(instance_type, ami_id, key_name, security_group, count, tags):
    tags_dict = dict(tags)
    table_data = [
        [click.style("+", fg="green"), "Instance Type", instance_type],
        [click.style("+", fg="green"), "AMI ID", ami_id],
        [click.style("+", fg="green"), "Key Name", key_name],
        [click.style("+", fg="green"), "Security Group", security_group],
        [click.style("+", fg="green"), "Count", count],
        [click.style("+", fg="green"), "Tags", tags_dict]
    ]
    click.echo(click.style("\nStaging area: Creating EC2 instance(s) with the following configuration:\n", fg="green"))
    click.echo(tabulate(table_data, headers=["", "Attribute", "Value"], tablefmt="grid"))

    if click.confirm(click.style("Do you want to proceed with creating the instance(s)?", fg="green"), default=True):
        version_id = str(uuid.uuid4())  # Generate a unique version ID
        comment = click.prompt(click.style("Enter a comment for this version", fg="green"))

        try:
            instances = create_ec2_instances(instance_type, ami_id, key_name, security_group, count, tags_dict)
            if instances is None:
                raise Exception("Instance creation failed. Aborting operation.")

            click.echo(click.style("Instances created successfully.", fg="green"))
            for idx, instance in enumerate(instances):
                click.echo(click.style(f"Instance {idx+1}: ID = {instance['InstanceId']}", fg="green"))

            version_content = [{'InstanceId': instance['InstanceId'], 'InstanceType': instance['InstanceType'], 'ImageId': instance['ImageId'], 'KeyName': instance['KeyName'], 'SecurityGroups': instance['SecurityGroups'], 'Tags': instance.get('Tags', [])} for instance in instances]

            if check_bucket_exists(VERSION_BUCKET_NAME):
                save_version_info_to_bucket(version_id, comment, version_content)
            else:
                if click.confirm("Do you want to save the version information in a bucket?", default=False):
                    create_version_bucket()
                    save_version_info_to_bucket(version_id, comment, version_content)
                else:
                    save_version_info_locally(version_id, comment, version_content)
        except Exception as e:
            click.echo(click.style(f"Failed to create instances: {e}", fg="red"))
    else:
        click.echo(click.style("Instance creation aborted.", fg="yellow"))


# Load version info
def load_version_info(version_id):
    key = load_key()
    if os.path.exists(os.path.join(VERSION_DIR, f"{version_id}.enc")):
        with open(os.path.join(VERSION_DIR, f"{version_id}.enc"), 'rb') as version_file:
            encrypted_version_info = version_file.read()
        decrypted_version_info = decrypt_data(encrypted_version_info, key)
        return json.loads(decrypted_version_info)
    else:
        try:
            credentials = load_aws_credentials()
            s3 = boto3.client('s3', **credentials)
            response = s3.get_object(Bucket=VERSION_BUCKET_NAME, Key=f"{version_id}.enc")
            encrypted_version_info = response['Body'].read()
            decrypted_version_info = decrypt_data(encrypted_version_info, key)
            return json.loads(decrypted_version_info)
        except ClientError as e:
            click.echo(click.style(f"No version information found for ID {version_id}.", fg="red"))
            return None




@cli.command(name="recreate-ec2", help="Recreate EC2 instances using a version ID.")
@click.option('--version-id', required=True, help="Version ID to recreate instances from")
def recreate_ec2(version_id):
    version_info = load_version_info(version_id)
    if not version_info:
        click.echo("No version information found.")
        return

    instances_to_recreate = version_info['content']

    click.echo(click.style(f"\nStaging area: Recreating EC2 instance(s):", fg="green"))
    table_data = []
    for idx, instance in enumerate(instances_to_recreate):
        table_data.append([click.style("+", fg="green"), "Instance Type", instance.get('InstanceType', 'Unknown')])
        table_data.append([click.style("+", fg="green"), "AMI ID", instance.get('ImageId', 'Unknown')])
        table_data.append([click.style("+", fg="green"), "Key Name", instance.get('KeyName', 'Unknown')])
        security_groups = instance.get('SecurityGroups', [])
        security_group_ids = [sg['GroupId'] for sg in security_groups] if security_groups else None
        table_data.append([click.style("+", fg="green"), "Security Group", security_group_ids if security_group_ids else 'None'])
        table_data.append([click.style("+", fg="green"), "Tags", instance.get('Tags', [])])
    click.echo(tabulate(table_data, headers=["", "Attribute", "Value"], tablefmt="grid"))

    if click.confirm(click.style("Do you want to proceed with recreating the instance(s)?", fg="green"), default=True):
        new_version_id = str(uuid.uuid4())
        comment = click.prompt(click.style("Enter a new comment for this version", fg="green"))

        try:
            recreated_instances = []
            for instance in instances_to_recreate:
                created_instances = create_ec2_instances(
                    instance_type=instance.get('InstanceType', 'Unknown'),
                    ami_id=instance.get('ImageId', 'Unknown'),
                    key_name=instance.get('KeyName', 'Unknown'),
                    security_group=security_group_ids[0] if security_group_ids else None,
                    count=1,
                    tags={tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                )
                if created_instances is None:
                    raise Exception("Instance recreation failed. Aborting operation.")
                recreated_instances.extend(created_instances)

            click.echo(click.style("Instances recreated successfully.", fg="green"))
            for idx, instance in enumerate(recreated_instances):
                click.echo(click.style(f"Instance {idx+1}: ID = {instance['InstanceId']}", fg="green"))

            if check_bucket_exists(VERSION_BUCKET_NAME):
                save_version_info_to_bucket(new_version_id, comment, recreated_instances)
            else:
                if click.confirm("Do you want to save the version information in a bucket?", default=False):
                    create_version_bucket()
                    save_version_info_to_bucket(new_version_id, comment, recreated_instances)
                else:
                    save_version_info_locally(new_version_id, comment, recreated_instances)
        except Exception as e:
            click.echo(click.style(f"Failed to recreate instances: {e}", fg="red"))
    else:
        click.echo(click.style("Instance recreation aborted.", fg="yellow"))



# List versions function
def list_versions():
    if not os.path.exists(KEY_FILE):
        click.echo("No encryption key found. Please run 'dob configure-aws' to set up your credentials.")
        return []

    key = load_key()
    versions = []

    # Check local versions
    for file_name in os.listdir(VERSION_DIR):
        if file_name.endswith(".enc"):
            version_id = file_name.split(".")[0]
            version_info = load_version_info(version_id)
            if version_info:
                timestamp = datetime.fromtimestamp(os.path.getmtime(os.path.join(VERSION_DIR, f"{version_id}.enc"))).strftime('%Y-%m-%d %H:%M:%S')
                instance_count = len(version_info['content'])
                versions.append((version_id, version_info.get('comment', ''), timestamp, instance_count))

    return versions

# View version command
@cli.command(name="view-version", help="View version information.")
@click.option('-o', '--output', type=click.Choice(['table', 'wide']), default='table', help="Output format")
def view_version(output):
    versions = list_versions()
    if not versions:
        click.echo("No versions available. Ensure your credentials are configured properly.")
        return

    if output == 'table':
        table = [[version_id, comment, timestamp, count] for version_id, comment, timestamp, count in versions]
        headers = ["Version ID", "Comment", "Date", "Time", "Count"]
        click.echo(tabulate(table, headers, tablefmt="grid"))
    elif output == 'wide':
        for version_id, comment, timestamp, count in versions:
            version_info = load_version_info(version_id)
            click.echo(click.style(f"Version ID: {version_id}", fg="green"))
            click.echo(click.style(f"Comment: {comment}", fg="green"))
            click.echo(click.style(f"Timestamp: {timestamp}", fg="green"))
            click.echo(click.style(f"Count: {count}", fg="green"))
            click.echo(click.style(json.dumps(version_info['content'], indent=2), fg="green"))
            click.echo("-" * 80)



@cli.command(name="list-ec2", help="List EC2 instances in a table format.")
@click.option('--instance-ids', multiple=True, help="Filter by instance IDs")
def list_ec2_instances(instance_ids):
    credentials = load_aws_credentials()
    if not credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return

    ec2 = boto3.client('ec2', **credentials)
    try:
        if instance_ids:
            response = ec2.describe_instances(InstanceIds=instance_ids)
        else:
            response = ec2.describe_instances()

        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_type = instance['InstanceType']
                key_name = instance.get('KeyName', '-')
                security_groups = ', '.join([sg['GroupId'] for sg in instance.get('SecurityGroups', [])])
                state = instance['State']['Name']
                public_ip = instance.get('PublicIpAddress', 'N/A')
                state_symbol = {
                    'running': click.style('+', fg='green'),
                    'stopped': click.style('-', fg='red'),
                    'terminated': click.style('x', fg='yellow')
                }.get(state, state)
                launch_time = instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
                tags = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in instance.get('Tags', [])])
                instances.append([
                    state_symbol, instance_id, instance_type, key_name, security_groups,
                    launch_time, tags, public_ip
                ])

        headers = ["State", "Instance ID", "Instance Type", "Key Name", "Security Groups", "Launch Time", "Tags", "Public IP"]
        click.echo(tabulate(instances, headers, tablefmt="grid"))
    except ClientError as e:
        click.echo(click.style(f"Failed to list instances: {e}", fg="red"))

@cli.command(name="list-s3", help="List S3 buckets in a table format.")
def list_s3_buckets():
    credentials = load_aws_credentials()
    if not credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return

    s3 = boto3.client('s3', **credentials)
    try:
        response = s3.list_buckets()
        buckets = []
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            creation_date = bucket['CreationDate'].strftime('%Y-%m-%d %H:%M:%S')
            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                enc_rules = encryption['ServerSideEncryptionConfiguration']['Rules']
                encryption_status = 'Enabled'
            except ClientError:
                encryption_status = 'None'

            try:
                object_count = s3.list_objects_v2(Bucket=bucket_name)['KeyCount']
            except ClientError:
                object_count = 'Unknown'

            buckets.append([
                bucket_name, creation_date, encryption_status, object_count
            ])

        headers = ["Bucket Name", "Creation Date", "Encryption", "Number of Objects"]
        click.echo(tabulate(buckets, headers, tablefmt="grid"))
    except ClientError as e:
        click.echo(click.style(f"Failed to list buckets: {e}", fg="red"))

@cli.command(name="list-objects", help="List objects in a specific S3 bucket in a table format.")
@click.argument('bucket_name')
def list_s3_objects(bucket_name):
    credentials = load_aws_credentials()
    if not credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return

    s3 = boto3.client('s3', **credentials)
    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' not in response:
            click.echo(click.style(f"No objects found in bucket {bucket_name}.", fg="yellow"))
            return

        objects = []
        for obj in response['Contents']:
            key = obj['Key']
            size = obj['Size']
            last_modified = obj['LastModified'].strftime('%Y-%m-%d %H:%M:%S')
            storage_class = obj['StorageClass']
            objects.append([
                key, size, last_modified, storage_class
            ])

        headers = ["Object Key", "Size (Bytes)", "Last Modified", "Storage Class"]
        click.echo(tabulate(objects, headers, tablefmt="grid"))
    except ClientError as e:
        click.echo(click.style(f"Failed to list objects in bucket {bucket_name}: {e}", fg="red"))

@cli.command(name="delete-object", help="Delete an object from an S3 bucket.")
@click.argument('bucket_name')
@click.argument('object_key')
def delete_object(bucket_name, object_key):
    click.echo(click.style("Warning: This action is irreversible and you will not be able to recreate the object. No version information will be saved.", fg="red"))
    if click.confirm(click.style("Do you want to proceed with deleting the object?", fg="red"), default=False):
        comment = click.prompt(click.style("Enter a comment for this deletion", fg="red"))
        try:
            credentials = load_aws_credentials()
            if credentials:
                s3 = boto3.client('s3', **credentials)
                s3.delete_object(Bucket=bucket_name, Key=object_key)
                click.echo(click.style(f"Object '{object_key}' deleted successfully from bucket '{bucket_name}'.", fg="green"))
            else:
                click.echo("AWS credentials not found. Please configure them first.")
        except ClientError as e:
            click.echo(click.style(f"Failed to delete object: {e}", fg="red"))
    else:
        click.echo(click.style("Object deletion aborted.", fg="yellow"))

@cli.command(name="delete-bucket", help="Delete an S3 bucket.")
@click.argument('bucket_name')
def delete_bucket(bucket_name):
    click.echo(click.style("Warning: This action is irreversible and you will not be able to recreate the bucket or its contents. No version information will be saved.", fg="red"))
    if click.confirm(click.style("Do you want to proceed with deleting the bucket?", fg="red"), default=False):
        try:
            credentials = load_aws_credentials()
            if credentials:
                s3 = boto3.client('s3', **credentials)
                response = s3.list_objects_v2(Bucket=bucket_name)
                if 'Contents' in response:
                    for obj in response['Contents']:
                        s3.delete_object(Bucket=bucket_name, Key=obj['Key'])
                s3.delete_bucket(Bucket=bucket_name)
                click.echo(click.style(f"Bucket '{bucket_name}' and all its contents deleted successfully.", fg="green"))
            else:
                click.echo("AWS credentials not found. Please configure them first.")
        except ClientError as e:
            click.echo(click.style(f"Failed to delete bucket: {e}", fg="red"))
    else:
        click.echo(click.style("Bucket deletion aborted.", fg="yellow"))

@cli.command(help="Stop AWS instances.")
@click.option('--instance_ids', required=True, help='Space-separated IDs of the AWS instances to stop')
def stop_aws_instances(instance_ids):
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return

    instance_ids_list = instance_ids.split()
    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.stop_instances(InstanceIds=instance_ids_list)
        stopped_instance_ids = [instance['InstanceId'] for instance in response['StoppingInstances']]
        click.echo(f"Instances stopped successfully: {', '.join(stopped_instance_ids)}")
    except NoRegionError:
        click.echo("You must specify a region.")
    except NoCredentialsError:
        click.echo("AWS credentials not found.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error stopping instances: {e}")

@cli.command(help="Start AWS instances.")
@click.option('--instance_ids', required=True, help='Space-separated IDs of the AWS instances to start')
def start_aws_instances(instance_ids):
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return

    instance_ids_list = instance_ids.split()
    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.start_instances(InstanceIds=instance_ids_list)
        started_instance_ids = [instance['InstanceId'] for instance in response['StartingInstances']]
        click.echo(f"Instances started successfully: {', '.join(started_instance_ids)}")
    except NoRegionError:
        click.echo("You must specify a region.")
    except NoCredentialsError:
        click.echo("AWS credentials not found.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error starting instances: {e}")

MAX_RETRIES = 30
RETRY_INTERVAL = 10
WAIT_TIME_AFTER_CREATION = 120

def wait_for_instance_ready(ec2, instance_id):
    """Wait until the instance is in a running state and has passed status checks."""
    for _ in tqdm(range(MAX_RETRIES), desc="Waiting for instance to be ready", unit="s"):
        try:
            response = ec2.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            state = instance['State']['Name']
            if state == 'running':
                click.echo(f"Instance {instance_id} is running.")
                return True
        except Exception as e:
            click.echo(f"Error checking instance status: {e}")
        time.sleep(RETRY_INTERVAL)
    raise Exception(f"Instance {instance_id} did not reach 'running' state within the timeout period.")

def execute_commands_on_instance(instance_id, commands):
    """Execute commands on an instance."""
    ssm = boto3.client('ssm', **load_aws_credentials())
    for platform, cmds in commands.items():
        if platform in ["default", "linux", "ubuntu", "rhel"]:
            try:
                for command in tqdm(cmds, desc=f"Executing commands on instance {instance_id}", unit="cmd"):
                    click.echo(f"Executing command on instance {instance_id} (Platform: {platform}): {command}")
                    response = ssm.send_command(
                        InstanceIds=[instance_id],
                        DocumentName="AWS-RunShellScript",
                        Parameters={'commands': [command]}
                    )
                    command_id = response['Command']['CommandId']
                    check_command_status(ssm, instance_id, command_id)
            except Exception as e:
                click.echo(f"Error executing command on instance {instance_id}: {e}")
                time.sleep(RETRY_INTERVAL)

def check_command_status(ssm, instance_id, command_id):
    """Check the status of the SSM command."""
    for _ in range(MAX_RETRIES):
        response = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        status = response['Status']
        if status in ['Success', 'Failed']:
            click.echo(f"Command status on instance {instance_id}: {status}")
            if status == 'Failed':
                raise Exception(f"Command failed with status: {status}")
            return
        time.sleep(RETRY_INTERVAL)
    raise Exception(f"Command status check failed after {MAX_RETRIES * RETRY_INTERVAL} seconds.")

@cli.command(name="dob-screenplay", help="Execute a DOB screenplay to create and manage worker instances.")
@click.argument('script')
def dob_screenplay(script):
    """Execute a DOB screenplay."""
    if not os.path.exists(script):
        click.echo(f"Script file '{script}' does not exist.")
        return

    with open(script, 'r') as f:
        screenplay = yaml.safe_load(f)

    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return

    ec2 = boto3.client('ec2', **aws_credentials)

    try:
        for instance in screenplay['instances']:
            instance_params = {
                'ImageId': instance['image_id'],
                'InstanceType': instance['instance_type'],
                'MinCount': instance['count'],
                'MaxCount': instance['count'],
                'SecurityGroupIds': [load_master_info()['security_group']],
                'KeyName': load_master_info()['key_pair'],
                'TagSpecifications': [{
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Role', 'Value': 'Worker'},
                        {'Key': 'WorkerID', 'Value': instance.get('worker_id', 'worker')}
                    ]
                }]
            }

            response = ec2.run_instances(**instance_params)
            instance_ids = [inst['InstanceId'] for inst in response['Instances']]
            click.echo(f"Instances created successfully: {', '.join(instance_ids)}")

            for instance_id in instance_ids:
                wait_for_instance_ready(ec2, instance_id)
                time.sleep(WAIT_TIME_AFTER_CREATION)

                platform = instance.get('platform', 'default')
                platform_commands = screenplay['commands'].get(platform, screenplay['commands']['default'])
                for command in platform_commands:
                    execute_commands_on_instance(instance_id, command)

    except Exception as e:
        click.echo(f"Error creating instances: {e}")

@cli.command(name="download-s3", help="Download a file from S3.")
@click.argument('bucket_name')
@click.argument('s3_key')
@click.argument('file_path')
def download_s3(bucket_name, s3_key, file_path):
    """Download a file from S3."""
    try:
        credentials = load_aws_credentials()
        if credentials:
            s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
            with open(file_path, 'wb') as f:
                s3.download_fileobj(bucket_name, s3_key, f)
            click.echo(f"File downloaded successfully from bucket '{bucket_name}' with key '{s3_key}' to '{file_path}'.")
        else:
            click.echo("AWS credentials not found. Please configure them first.")
    except ClientError as e:
        click.echo(f"Failed to download file from S3: {e}")

@cli.command(name="copy-s3-object", help="Copy an object from one S3 bucket to another.")
@click.argument('source_bucket')
@click.argument('source_key')
@click.argument('destination_bucket')
@click.argument('destination_key')
def copy_s3_object(source_bucket, source_key, destination_bucket, destination_key):
    """Copy an object from one S3 bucket to another."""
    try:
        credentials = load_aws_credentials()
        if credentials:
            s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
            copy_source = {'Bucket': source_bucket, 'Key': source_key}
            s3.copy(copy_source, destination_bucket, destination_key)
            click.echo(f"Object copied successfully from '{source_bucket}/{source_key}' to '{destination_bucket}/{destination_key}'.")
        else:
            click.echo("AWS credentials not found. Please configure them first.")
    except ClientError as e:
        click.echo(f"Failed to copy object: {e}")

@cli.command(name="upload-s3", help="Upload a file to S3.")
@click.argument('file_path')
@click.argument('bucket_name')
@click.argument('s3_key')
def upload_s3(file_path, bucket_name, s3_key):
    """Upload a file to S3."""
    try:
        credentials = load_aws_credentials()
        if credentials:
            s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
            with open(file_path, 'rb') as f:
                s3.upload_fileobj(f, bucket_name, s3_key)
            click.echo(f"File uploaded successfully to bucket '{bucket_name}' with key '{s3_key}'.")
        else:
            click.echo("AWS credentials not found. Please configure them first.")
    except ClientError as e:
        click.echo(f"Failed to upload file to S3: {e}")

@cli.command(name="create-s3-bucket", help="Create one or more S3 buckets.")
@click.argument('bucket_names', nargs=-1)
def create_s3_bucket(bucket_names):
    """Create one or more S3 buckets."""
    try:
        credentials = load_aws_credentials()
        if credentials:
            s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
            for bucket_name in bucket_names:
                s3.create_bucket(Bucket=bucket_name)
                click.echo(f"Bucket '{bucket_name}' created successfully.")
        else:
            click.echo("AWS credentials not found. Please configure them first.")
    except ClientError as e:
        click.echo(f"Failed to create bucket(s): {e}")

@cli.command(name="delete-s3-object", help="Delete an object from an S3 bucket.")
@click.argument('bucket_name')
@click.argument('object_key')
def delete_s3_object(bucket_name, object_key):
    """Delete an object from an S3 bucket."""
    click.echo(click.style("Warning: This action is irreversible and you will not be able to recreate the object. No version information will be saved.", fg="red"))
    if click.confirm(click.style("Do you want to proceed with deleting the object?", fg="red"), default=False):
        comment = click.prompt(click.style("Enter a comment for this deletion", fg="red"))
        try:
            credentials = load_aws_credentials()
            if credentials:
                s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
                s3.delete_object(Bucket=bucket_name, Key=object_key)
                click.echo(click.style(f"Object '{object_key}' deleted successfully from bucket '{bucket_name}'.", fg="green"))
            else:
                click.echo("AWS credentials not found. Please configure them first.")
        except ClientError as e:
            click.echo(click.style(f"Failed to delete object: {e}", fg="red"))
    else:
        click.echo(click.style("Object deletion aborted.", fg="yellow"))

@cli.command(name="delete-s3-bucket", help="Delete one or more S3 buckets.")
@click.argument('bucket_names', nargs=-1)
def delete_s3_bucket(bucket_names):
    """Delete one or more S3 buckets."""
    click.echo(click.style("Warning: This action is irreversible and you will not be able to recreate the bucket or its contents. No version information will be saved.", fg="red"))
    if click.confirm(click.style("Do you want to proceed with deleting the bucket(s)?", fg="red"), default=False):
        try:
            credentials = load_aws_credentials()
            if credentials:
                s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
                for bucket_name in bucket_names:
                    response = s3.list_objects_v2(Bucket=bucket_name)
                    if 'Contents' in response:
                        for obj in response['Contents']:
                            s3.delete_object(Bucket=bucket_name, Key=obj['Key'])
                    s3.delete_bucket(Bucket=bucket_name)
                    click.echo(click.style(f"Bucket '{bucket_name}' and all its contents deleted successfully.", fg="green"))
            else:
                click.echo("AWS credentials not found. Please configure them first.")
        except ClientError as e:
            click.echo(click.style(f"Failed to delete bucket: {e}", fg="red"))
    else:
        click.echo(click.style("Bucket deletion aborted.", fg="yellow"))

@cli.command(name="list-workers", help="List all registered workers with detailed information.")
def list_workers():
    """List all registered workers with detailed information."""
    token = load_token()
    if not token:
        click.echo("No token found. Please log in first.")
        return

    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(f"{API_BASE_URL}/api/workers", headers=headers)

    if response.status_code == 200:
        workers = response.json().get('workers', [])
        if workers:
            headers = ["Worker ID", "Worker URL"]
            table = [[worker['worker_id'], worker['worker_url']] for worker in workers]
            click.echo(tabulate(table, headers, tablefmt="grid"))
        else:
            click.echo("No registered workers found.")
    else:
        click.echo("Failed to retrieve workers information.")
        click.echo(response.json().get('message'))

@cli.command(name="solve", help="Solve an issue using the knowledge base.")
@click.option('--issue', prompt='Describe the issue', help='The issue you are facing')
def solve(issue):
    """Solve an issue using the knowledge base."""
    token = load_token()
    if not token:
        click.echo("No token found. Please log in first.")
        return

    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    response = requests.post(f"{API_BASE_URL}/api/solve", headers=headers, json={'issue': issue})

    if response.status_code == 200:
        solution = response.json().get('solution')
        if solution:
            click.echo("Solution:")
            click.echo(solution)
        else:
            click.echo("No solution found for the given issue.")
    else:
        click.echo("Failed to retrieve solution.")
        click.echo(response.json().get('message'))

if __name__ == '__main__':
    cli()
    app.run(debug=True)
