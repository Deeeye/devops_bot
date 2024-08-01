import subprocess
import paramiko
import os
import base64
import requests
import click
import uuid
import json
import time
import yaml
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from flask import Flask
from cryptography.fernet import Fernet
from datetime import datetime
from tabulate import tabulate
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from botocore.exceptions import ClientError

cli = click.Group()

API_BASE_URL = "https://devopsbot-testserver.online"


KUBECONFIG_KEY = "kubeconfig"
KEY_FILE = os.path.expanduser("~/.ssh/id_rsa")
JENKINS_CREDENTIALS_BUCKET = 'jenkins-credentials.dob'
JENKINS_CREDENTIALS_FILE = 'jenkins_credentials.enc'
JENKINS_KEY_FILE = 'jenkins_key.key'
BASE_DIR = os.path.expanduser("~/.etc/devops-bot")
VERSION_DIR = os.path.join(BASE_DIR, "version")
AWS_CREDENTIALS_FILE = os.path.join(BASE_DIR, "aws_credentials.enc")
KEY_FILE = os.path.join(BASE_DIR, "key.key")
VERSION_BUCKET_NAME = "devops-bot-version-bucket"
DEVOPS_BOT_TOKEN_FILE = os.path.join(BASE_DIR, "devops_bot_token")
DOB_SCREENPLAY_FILE = os.path.join(BASE_DIR, "dob_screenplay.yaml")
KUBECONFIG_PATH = os.path.expanduser('~/.kube/config')
S3_BUCKET_NAME = "dob-k8s-config"
S3_KUBECONFIG_KEY = "kubeconfig"

app = Flask(__name__)

MASTER_INFO_FILE = os.path.expanduser("~/.devops_master_info")


# Save kubeconfig
def save_kubeconfig(kubeconfig_data):
    ensure_private_folder()
    if not os.path.exists(os.path.dirname(KUBECONFIG_PATH)):
        os.makedirs(os.path.dirname(KUBECONFIG_PATH))
    with open(KUBECONFIG_PATH, 'w') as f:
        f.write(kubeconfig_data)
    os.chmod(KUBECONFIG_PATH, 0o600)

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
    ensure_user_folder()
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


def ensure_private_folder():
    """Ensure the private folder for storing master info exists with restricted permissions."""
    private_folder = os.path.dirname(MASTER_INFO_FILE)
    if not os.path.exists(private_folder):
        os.makedirs(private_folder, mode=0o700, exist_ok=True)  # rwx------ permissions


# Ensure user folder
def ensure_user_folder():
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR, mode=0o700, exist_ok=True)

# Ensure version folder
def ensure_version_folder():
    if not os.path.exists(VERSION_DIR):
        os.makedirs(VERSION_DIR, mode=0o700, exist_ok=True)

# Generate encryption key
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    click.echo("Encryption key generated and saved.")

# Load encryption key
def load_key():
    return open(KEY_FILE, 'rb').read()

# Encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return encrypted

# Decrypt data
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data).decode()
    return decrypted

# Save AWS credentials encrypted
def save_aws_credentials(access_key, secret_key, region):
    ensure_user_folder()
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

def check_bucket_exists(bucket_name):
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', **credentials)
        s3.head_bucket(Bucket=bucket_name)
        return True
    except ClientError:
        return False

# Load AWS credentials and decrypt them
def load_aws_credentials():
    credentials = None
    try:
        if os.path.exists(AWS_CREDENTIALS_FILE):
            key = load_key()
            with open(AWS_CREDENTIALS_FILE, 'rb') as cred_file:
                encrypted_credentials = cred_file.read()
            decrypted_credentials = decrypt_data(encrypted_credentials, key)
            credentials = json.loads(decrypted_credentials)
    except FileNotFoundError:
        pass
    return credentials

def create_s3_bucket(bucket_name, region=None):
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client(
            's3',
            aws_access_key_id=credentials['aws_access_key_id'],
            aws_secret_access_key=credentials['aws_secret_access_key'],
            region_name=region
        ) if credentials else boto3.client('s3', region_name=region)

        create_bucket_config = {'LocationConstraint': region} if region and region != 'us-east-1' else None
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration=create_bucket_config
        ) if create_bucket_config else s3.create_bucket(Bucket=bucket_name)

        click.echo(f"Bucket {bucket_name} created successfully in region {region}.")
        return True
    except (NoCredentialsError, PartialCredentialsError) as e:
        click.echo(f"Error with AWS credentials: {e}")
    except ClientError as e:
        click.echo(f"Error creating bucket: {e}")
    return False



def create_s3_bucket(bucket_name, region=None):
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client(
            's3',
            aws_access_key_id=credentials['aws_access_key_id'],
            aws_secret_access_key=credentials['aws_secret_access_key'],
            region_name=region
        ) if credentials else boto3.client('s3', region_name=region)

        create_bucket_config = {'LocationConstraint': region} if region and region != 'us-east-1' else None
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration=create_bucket_config
        ) if create_bucket_config else s3.create_bucket(Bucket=bucket_name)

        click.echo(f"Bucket {bucket_name} created successfully in region {region}.")
        return True
    except (NoCredentialsError, PartialCredentialsError) as e:
        click.echo(f"Error with AWS credentials: {e}")
    except ClientError as e:
        click.echo(f"Error creating bucket: {e}")
    return False



@cli.command(name="create-s3-bucket", help="Create one or more S3 buckets.")
@click.argument('bucket_names', nargs=-1)
@click.option('--region', default=None, help='AWS region to create the bucket in.')
@click.option('--count', default=1, help='Number of buckets to create.')
def create_s3_bucket_cli(bucket_names, region, count):
    for bucket_name in bucket_names:
        for i in range(count):
            unique_bucket_name = f"{bucket_name}-{i}" if count > 1 else bucket_name
            if create_s3_bucket(unique_bucket_name, region):
                click.echo(click.style(f"Bucket {unique_bucket_name} created successfully.", fg="green"))
            else:
                click.echo(click.style(f"Failed to create bucket {unique_bucket_name}.", fg="red"))

@cli.command(name="create-s3-bucket-dob", help="Create S3 buckets using dob-screenplay YAML file.")
@click.argument('dob_screenplay', type=click.Path(exists=True))
def create_s3_bucket_dob(dob_screenplay):
    with open(dob_screenplay, 'r') as f:
        dob_content = yaml.safe_load(f)

    click.echo(click.style("\nStaging area: Creating S3 bucket(s) using dob-screenplay:", fg="green"))
    for idx, resource in enumerate(dob_content['resources']['s3_buckets']):
        data = [
            [click.style("+", fg="green"), "Bucket Name", resource['name']],
            [click.style("+", fg="green"), "Region", resource['region']]
        ]
        table = tabulate(data, headers=["", "Attribute", "Value"], tablefmt="grid")
        click.echo(table)

    if click.confirm(click.style("Do you want to proceed with creating the bucket(s)?", fg="green"), default=True):
        all_buckets_created = True
        for resource in dob_content['resources']['s3_buckets']:
            if not create_s3_bucket(resource['name'], resource['region']):
                all_buckets_created = False

        if all_buckets_created:
            click.echo(click.style("All buckets created successfully.", fg="green"))
        else:
            click.echo(click.style("Some buckets failed to create. Check the logs for details.", fg="red"))
    else:
        click.echo(click.style("Bucket creation aborted.", fg="yellow"))

# Upload encrypted credentials to S3
def upload_encrypted_credentials_to_s3(bucket_name):
    try:
        key = load_key()
        with open(AWS_CREDENTIALS_FILE, 'rb') as cred_file:
            encrypted_credentials = cred_file.read()
            click.echo("Encrypted credentials loaded for upload.")

        credentials = load_aws_credentials()
        s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
        s3.put_object(Bucket=bucket_name, Key='aws_credentials.enc', Body=encrypted_credentials)
        click.echo(f"Encrypted credentials uploaded to bucket {bucket_name} successfully.")
    except (NoCredentialsError, PartialCredentialsError) as e:
        click.echo(f"Error with AWS credentials: {e}")
    except ClientError as e:
        click.echo(f"Error uploading encrypted credentials to bucket: {e}")

# Save the dob-screenplay content to a file
def save_dob_screenplay(dob_screenplay_content):
    with open(DOB_SCREENPLAY_FILE, 'w') as f:
        yaml.dump(dob_screenplay_content, f)
    click.echo("dob-screenplay content saved locally.")

@cli.command(name="configure-aws", help="Configure AWS credentials.")
@click.option('--aws_access_key_id', required=True, help="AWS Access Key ID")
@click.option('--aws_secret_access_key', required=True, help="AWS Secret Access Key")
@click.option('--region', required=True, help="AWS Region")
def configure_aws(aws_access_key_id, aws_secret_access_key, region):
    if not os.path.exists(KEY_FILE):
        generate_key()

    save_aws_credentials(aws_access_key_id, aws_secret_access_key, region)
    click.echo("AWS credentials configured and saved locally successfully.")

    if click.confirm("Do you want to save these credentials in a cloud storage like S3?", default=True):
        num_buckets = click.prompt("How many storage buckets do you require?", type=int)
        bucket_names = [click.prompt(f"Enter name for bucket {i+1}") for i in range(num_buckets)]

        dob_screenplay_content = {
            'version': '1.0',
            'resources': {
                's3_buckets': [
                    {'name': bucket_name, 'region': region} for bucket_name in bucket_names
                ]
            }
        }

        save_dob_screenplay(dob_screenplay_content)

        click.echo(yaml.dump(dob_screenplay_content))
        if click.confirm("Do you want to proceed with creating the above buckets?", default=True):
            for bucket in dob_screenplay_content['resources']['s3_buckets']:
                create_s3_bucket(bucket['name'], bucket['region'])
                upload_encrypted_credentials_to_s3(bucket['name'])

            click.echo("All buckets created successfully and encrypted credentials uploaded.")
        else:
            click.echo("Bucket creation aborted.")

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
            verify_token(username, token)
        else:
            click.echo("Failed to retrieve token.")
    else:
        click.echo("Invalid username or password")

def verify_token(username, token):
    for _ in range(12):  # 1 minute with 5-second intervals
        response = requests.post(f"{API_BASE_URL}/api/verify_token", headers={'Content-Type': 'application/json'}, json={"username": username, "token": token})
        if response.status_code == 200:
            click.echo(f"Token verified successfully for {username}.")
            return
        time.sleep(5)
    click.echo("Token verification failed.")

def save_token(token):
    ensure_user_folder()
    with open(DEVOPS_BOT_TOKEN_FILE, 'w') as token_file:
        token_file.write(token)
    os.chmod(DEVOPS_BOT_TOKEN_FILE, 0o600)
    click.echo("Token saved locally.")

# EC2


# Serialize instance information
def serialize_instance_info(instance):
    for key, value in instance.items():
        if isinstance(value, datetime):
            instance[key] = value.isoformat()
        elif isinstance(value, list):
            instance[key] = [serialize_instance_info(item) if isinstance(item, dict) else item for item in value]
        elif isinstance(value, dict):
            instance[key] = serialize_instance_info(value)
    return instance

def create_version_bucket():
    credentials = load_aws_credentials()
    if not credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return None

    s3 = boto3.client('s3', **credentials)
    try:
        if click.confirm("Do you want to create a new bucket for version information?", default=True):
            s3.create_bucket(Bucket=VERSION_BUCKET_NAME)
            click.echo(f"S3 bucket '{VERSION_BUCKET_NAME}' created successfully.")
    except ClientError as e:
        click.echo(click.style(f"Failed to create S3 bucket: {e}", fg="red"))

# Delete instance
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

# Utility function for deleting EC2 instances
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

# Assuming utility functions for encryption, AWS credential loading, version saving/loading are present

def save_version_info_locally(version_id, comment, content):
    ensure_version_folder()
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



def list_ec2_instances_to_file():
    credentials = load_aws_credentials()
    ec2 = boto3.client('ec2', **credentials)
    try:
        response = ec2.describe_instances()
        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_type = instance['InstanceType']
                key_name = instance.get('KeyName', '-')
                security_groups = ', '.join([sg['GroupId'] for sg in instance.get('SecurityGroups', [])])
                state = instance['State']['Name']
                state_symbol = {
                    'running': click.style('+', fg='green'),
                    'stopped': click.style('+', fg='red'),
                    'terminated': click.style('+', fg='yellow')
                }.get(state, state)
                launch_time = instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
                tags = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in instance.get('Tags', [])])
                public_ip = instance.get('PublicIpAddress', 'N/A')
                instances.append({
                    "State": state_symbol,
                    "Instance ID": instance_id,
                    "Instance Type": instance_type,
                    "Key Name": key_name,
                    "Security Groups": security_groups,
                    "Launch Time": launch_time,
                    "Tags": tags,
                    "Public IP": public_ip
                })

        with open('ec2_instances.json', 'w') as file:
            json.dump(instances, file)
        click.echo("EC2 instances information updated.")
    except ClientError as e:
        click.echo(click.style(f"Failed to list instances: {e}", fg="red"))


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


def list_versions():
    versions = []
    key = load_key()
    # Check local versions
    for file_name in os.listdir(VERSION_DIR):
        if file_name.endswith(".enc"):
            version_id = file_name.split(".")[0]
            version_info = load_version_info(version_id)
            if version_info:
                timestamp = datetime.fromtimestamp(os.path.getmtime(os.path.join(VERSION_DIR, f"{version_id}.enc"))).strftime('%Y-%m-%d %H:%M:%S')
                instance_count = len(version_info['content'])
                versions.append((version_id, version_info.get('comment', ''), timestamp, instance_count))
    # Check S3 versions
    credentials = load_aws_credentials()
    s3 = boto3.client('s3', **credentials)
    try:
        response = s3.list_objects_v2(Bucket=VERSION_BUCKET_NAME)
        for obj in response.get('Contents', []):
            version_id = obj['Key'].split(".")[0]
            version_info = load_version_info(version_id)
            if version_info:
                timestamp = obj['LastModified'].strftime('%Y-%m-%d %H:%M:%S')
                instance_count = len(version_info['content'])
                versions.append((version_id, version_info.get('comment', ''), timestamp, instance_count))
    except ClientError as e:
        click.echo(click.style(f"Error listing versions in S3: {e}", fg="red"))
    return versions

@cli.command(name="view-version", help="View version information.")
@click.option('-o', '--output', type=click.Choice(['table', 'wide']), default='table', help="Output format")
def view_version(output):
    versions = list_versions()
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

# List EC2 instances command

# List EC2 instances command
@cli.command(name="list-ec2", help="List EC2 instances in a table format.")
@click.option('--instance-ids', multiple=True, help="Filter by instance IDs")
def list_ec2_instances(instance_ids):
    credentials = load_aws_credentials()
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


# List S3 buckets command
@cli.command(name="list-s3", help="List S3 buckets in a table format.")
def list_s3_buckets():
    credentials = load_aws_credentials()
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

# List objects in a specific S3 bucket command
@cli.command(name="list-objects", help="List objects in a specific S3 bucket in a table format.")
@click.argument('bucket_name')
def list_s3_objects(bucket_name):
    credentials = load_aws_credentials()
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
            s3 = boto3.client('s3', **credentials)
            s3.delete_object(Bucket=bucket_name, Key=object_key)
            click.echo(click.style(f"Object '{object_key}' deleted successfully from bucket '{bucket_name}'.", fg="green"))
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
            s3 = boto3.client('s3', **credentials)
            # Empty the bucket before deleting
            response = s3.list_objects_v2(Bucket=bucket_name)
            if 'Contents' in response:
                for obj in response['Contents']:
                    s3.delete_object(Bucket=bucket_name, Key=obj['Key'])
            s3.delete_bucket(Bucket=bucket_name)
            click.echo(click.style(f"Bucket '{bucket_name}' and all its contents deleted successfully.", fg="green"))
        except ClientError as e:
            click.echo(click.style(f"Failed to delete bucket: {e}", fg="red"))
    else:
        click.echo(click.style("Bucket deletion aborted.", fg="yellow"))


def fetch_instance_details(instance_ids, credentials):
    ec2 = boto3.client('ec2', **credentials)
    max_retries = 10
    wait_time = 60

    for _ in range(max_retries):
        try:
            response = ec2.describe_instances(InstanceIds=instance_ids)
            all_running = True
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] != 'running':
                        all_running = False
                        break
                if not all_running:
                    break
            if all_running:
                return response['Reservations']
            else:
                time.sleep(wait_time)  # Wait before retrying
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                time.sleep(wait_time)  # Wait before retrying
            else:
                raise e
    raise Exception(f"Instances {instance_ids} did not reach running state within the allotted time.")



def create_ec2_instances(instances):
    for idx, resource in enumerate(instances):
        user_data = ''
        if 'user_data_path' in resource:
            with open(resource['user_data_path'], 'r') as user_data_file:
                user_data = user_data_file.read()
        elif 'user_data' in resource:
            user_data = resource['user_data']

        table_data = [
            [click.style("+", fg="green"), "Instance Type", resource['instance_type']],
            [click.style("+", fg="green"), "AMI ID", resource['ami_id']],
            [click.style("+", fg="green"), "Key Name", resource['key_name']],
            [click.style("+", fg="green"), "Security Group", resource['security_group']],
            [click.style("+", fg="green"), "Count", resource.get('count', 1)],
            [click.style("+", fg="green"), "Tags", resource.get('tags', {})],
            [click.style("+", fg="green"), "User Data", user_data]
        ]
        click.echo(tabulate(table_data, headers=["", "Attribute", "Value"], tablefmt="grid"))

    if click.confirm(click.style("Do you want to proceed with creating and configuring the instance(s)?", fg="green"), default=True):
        version_id = str(uuid.uuid4())  # Generate a unique version ID
        comment = click.prompt(click.style("Enter a comment for this version", fg="green"))

        try:
            instances_ids = []
            credentials = load_aws_credentials()
            for resource in instances:
                instance_type = resource['instance_type']
                ami_id = resource['ami_id']
                key_name = resource['key_name']
                security_group = resource['security_group']
                count = resource.get('count', 1)
                tags = resource.get('tags', {})
                user_data = ''
                if 'user_data_path' in resource:
                    with open(resource['user_data_path'], 'r') as user_data_file:
                        user_data = user_data_file.read()
                elif 'user_data' in resource:
                    user_data = resource['user_data']

                ec2 = boto3.client('ec2', **credentials)
                response = ec2.run_instances(
                    InstanceType=instance_type,
                    ImageId=ami_id,
                    KeyName=key_name,
                    SecurityGroupIds=[security_group],
                    MinCount=count,
                    MaxCount=count,
                    TagSpecifications=[{
                        'ResourceType': 'instance',
                        'Tags': [{'Key': k, 'Value': v} for k, v in tags.items()]
                    }],
                    UserData=user_data
                )

                instance_ids = [instance['InstanceId'] for instance in response['Instances']]
                instances_ids.extend(instance_ids)

            click.echo(f"Instances created with IDs: {', '.join(instances_ids)}")
            click.echo("Waiting for instances to be in running state...")
            reservations = fetch_instance_details(instance_ids, credentials)
            click.echo("Instances are now running.")

            for reservation in reservations:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    public_ip = instance.get('PublicIpAddress', 'No public IP')
                    click.echo(f"Instance {instance_id} has Public IP: {public_ip}")

            if check_bucket_exists(VERSION_BUCKET_NAME):
                save_version_info_to_bucket(version_id, comment, reservations)
            else:
                if click.confirm("Do you want to save the version information in a bucket?", default=False):
                    create_version_bucket()
                    save_version_info_to_bucket(version_id, comment, reservations)
                else:
                    save_version_info_locally(version_id, comment, reservations)

        except ClientError as e:
            click.echo(click.style(f"Failed to create and configure instances: {e}", fg="red"))

def create_s3_buckets(buckets):
    credentials = load_aws_credentials()
    s3 = boto3.client('s3', **credentials)
    for bucket in buckets:
        bucket_name = bucket['name']
        click.echo(click.style(f"Creating S3 bucket: {bucket_name}", fg="green"))
        try:
            s3.create_bucket(Bucket=bucket_name)
            click.echo(click.style(f"Bucket {bucket_name} created successfully.", fg="green"))
        except ClientError as e:
            click.echo(click.style(f"Failed to create bucket {bucket_name}: {e}", fg="red"))

def attach_ebs_volumes(volumes):
    credentials = load_aws_credentials()
    ec2 = boto3.client('ec2', **credentials)
    for volume in volumes:
        instance_id = volume['instance_id']
        volume_id = volume['volume_id']
        device = volume['device']
        click.echo(click.style(f"Attaching EBS volume {volume_id} to instance {instance_id} as {device}", fg="green"))
        try:
            ec2.attach_volume(
                VolumeId=volume_id,
                InstanceId=instance_id,
                Device=device
            )
            click.echo(click.style(f"Volume {volume_id} attached to instance {instance_id} as {device}.", fg="green"))
        except ClientError as e:
            click.echo(click.style(f"Failed to attach volume {volume_id} to instance {instance_id}: {e}", fg="red"))

def detach_ebs_volumes(volumes):
    credentials = load_aws_credentials()
    ec2 = boto3.client('ec2', **credentials)
    for volume in volumes:
        volume_id = volume['volume_id']
        click.echo(click.style(f"Detaching EBS volume {volume_id}", fg="green"))
        try:
            ec2.detach_volume(VolumeId=volume_id)
            click.echo(click.style(f"Volume {volume_id} detached successfully.", fg="green"))
        except ClientError as e:
            click.echo(click.style(f"Failed to detach volume {volume_id}: {e}", fg="red"))

@cli.command(name="create-ec2-dob", help="Create EC2 instances using dob-screenplay YAML file.")
@click.argument('dob_screenplay', type=click.Path(exists=True))
def create_ec2_dob(dob_screenplay):
    with open(dob_screenplay, 'r') as f:
        dob_content = yaml.safe_load(f)

    if 'resources' in dob_content:
        resources = dob_content['resources']
        if 'ec2_instances' in resources:
            create_ec2_instances(resources['ec2_instances'])
        if 's3_buckets' in resources:
            create_s3_buckets(resources['s3_buckets'])
        if 'attach_ebs_volumes' in resources:
            attach_ebs_volumes(resources['attach_ebs_volumes'])
        if 'detach_ebs_volumes' in resources:
            detach_ebs_volumes(resources['detach_ebs_volumes'])




def save_master_info(instance_id, public_ip, security_group, key_pair):
    """Save master instance information to a file."""
    ensure_private_folder()
    master_info = {
        'instance_id': instance_id,
        'public_ip': public_ip,
        'security_group': security_group,
        'key_pair': key_pair
    }
    with open(MASTER_INFO_FILE, 'w') as f:
        json.dump(master_info, f)
    os.chmod(MASTER_INFO_FILE, 0o600)  # rw-------

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

@cli.command(name="master-setup", help="Setup master instance information.")
def setup_master():
    """Setup master instance information."""
    try:
        instance_id, public_ip, security_group, key_pair = get_instance_metadata()
        save_master_info(instance_id, public_ip, security_group, key_pair)
        click.echo(f"Master setup complete with instance ID: {instance_id}, public IP: {public_ip}, security group: {security_group}, key pair: {key_pair}")
    except Exception as e:
        click.echo(f"Failed to setup master: {e}")

@cli.command(name="delete-worker", help="Delete a worker instance.")
@click.option('--worker_id', required=True, help='Unique ID for the worker node')
def delete_worker(worker_id):
    """Delete a worker instance."""
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.terminate_instances(InstanceIds=[worker_id])
        click.echo(f"Worker instance {worker_id} deleted successfully.")
    except boto3.exceptions.Boto3Error as e:
        click.echo(f"Error deleting worker instance: {e}")

@cli.command(name="stop-worker", help="Stop a worker instance.")
@click.option('--worker_id', required=True, help='Unique ID for the worker node')
def stop_worker(worker_id):
    """Stop a worker instance."""
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.stop_instances(InstanceIds=[worker_id])
        click.echo(f"Worker instance {worker_id} stopped successfully.")
    except boto3.exceptions.Boto3Error as e:
        click.echo(f"Error stopping worker instance: {e}")

@cli.command(name="list-workers", help="List all registered workers with detailed information.")
def list_workers():
    """List all registered workers."""
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.describe_instances(Filters=[{'Name': 'tag:Role', 'Values': ['worker']}])

        workers = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                if instance['State']['Name'] != 'terminated':
                    worker_info = {
                        'Worker ID': instance['InstanceId'],
                        'AMI': instance['ImageId'],
                        'IP Address': instance.get('PublicIpAddress', 'N/A'),
                        'CPU': instance['InstanceType'],
                        'RAM': instance['MemoryInfo']['SizeInMiB'] if 'MemoryInfo' in instance else 'N/A',
                        'Free Space': 'N/A',  # This would typically require an agent on the worker to report
                        'Task': 'N/A',  # This would require an agent on the worker to report
                        'Created At': instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
                    }
                    workers.append(worker_info)

        if workers:
            for worker in workers:
                for key, value in worker.items():
                    click.echo(f"{key}: {value}")
                click.echo('-' * 40)
        else:
            click.echo("No workers found.")
    except boto3.exceptions.Boto3Error as e:
        click.echo(f"Error listing workers: {e}")

@cli.command(name="assign-task", help="Assign a task to a specific worker.")
@click.option('--worker_id', required=True, help='Unique ID for the worker node')
@click.option('--task', required=True, help='Task command to be executed by the worker')
def assign_task(worker_id, task):
    """Assign a task to a specific worker."""
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.describe_instances(InstanceIds=[worker_id])
        worker_ip = response['Reservations'][0]['Instances'][0]['PublicIpAddress']

        response = requests.post(f"http://{worker_ip}:5001/execute_task", json={"command": task})
        if response.status_code == 200:
            click.echo(f"Task assigned to worker {worker_id} successfully.")
        else:
            click.echo(f"Failed to assign task. Error: {response.text}")
    except boto3.exceptions.Boto3Error as e:
        click.echo(f"Error assigning task: {e}")

@cli.command(name="create-worker", help="Create a worker instance and register it with the master.")
@click.option('--master_url', required=True, help='URL of the master node')
@click.option('--worker_id', required=True, help='Unique ID for the worker node')
@click.option('--params', required=True, help='Parameters for the AWS instance (e.g., "image_id=ami-0abcdef1234567890 instance_type=t2.micro")')
def create_worker(master_url, worker_id, params):
    """Create a worker instance and register it with the master."""
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    master_info = load_master_info()
    if not master_info:
        click.echo("No master information found. Please run 'devops-bot master-setup' first.")
        return

    params_dict = dict(param.split('=') for param in params.split())
    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.run_instances(
            ImageId=params_dict.get('image_id'),
            InstanceType=params_dict.get('instance_type'),
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[master_info['security_group']],
            KeyName=master_info['key_pair'],
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Role', 'Value': 'worker'},
                        {'Key': 'WorkerID', 'Value': worker_id}
                    ]
                }
            ]
        )
        instance_id = response['Instances'][0]['InstanceId']
        click.echo(f"Worker instance created successfully: {instance_id}")

        # Wait for the instance to be in the running state
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])

        try:
            public_ip = get_instance_public_ip(ec2, instance_id)
            click.echo(f"Public IP for instance {instance_id} is {public_ip}")
        except Exception as e:
            click.echo(f"Error: {e}")
            return

        worker_url = f"http://{public_ip}:5001"
        click.echo(f"Worker URL: {worker_url}")

        register_worker(master_url, worker_id, worker_url)

    except boto3.exceptions.Boto3Error as e:
        click.echo(f"Error creating worker instance: {e}")



def get_instance_public_ip(ec2, instance_id):
    """Fetch public IP address of an instance."""
    max_retries = 20  # Increased number of retries
    retry_interval = 10  # seconds

    for _ in range(max_retries):
        try:
            response = ec2.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            state = instance['State']['Name']
            public_ip = instance.get('PublicIpAddress')
            if state == 'running' and public_ip:
                return public_ip
        except boto3.exceptions.Boto3Error as e:
            pass  # Ignore errors and retry
        time.sleep(retry_interval)

    raise Exception(f"Instance {instance_id} did not reach 'running' state with a public IP within the timeout period.")

def register_worker(master_url, worker_id, worker_url):
    """Register a worker with the master node."""
    response = requests.post(f"{master_url}/register_worker", json={
        "worker_id": worker_id,
        "worker_url": worker_url
    })
    if response.status_code == 200:
        click.echo(f"Worker {worker_id} registered successfully with master.")
    else:
        click.echo(f"Failed to register worker {worker_id} with master. Error: {response.text}")

def load_master_info():
    """Load master instance information from a file."""
    try:
        with open(MASTER_INFO_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

@cli.command(name="start-master", help="Start the master server.")
@click.option('--host', default='0.0.0.0', help='Host to bind the server')
@click.option('--port', default=5001, help='Port to bind the server')
def start_master(host, port):
    app.run(host=host, port=port)


@cli.command(name="start-worker", help="Start worker node.")
@click.option('--master_url', required=True, help='URL of the master node')
@click.option('--worker_id', required=True, help='Unique ID for the worker node')
@click.option('--host', default='0.0.0.0', help='Host to run the worker node on')
@click.option('--port', default=5001, help='Port to run the worker node on')
def start_worker(master_url, worker_id, host, port):
    app = Flask(__name__)

    @app.route('/execute_task', methods=['POST'])
    def execute_task():
        data = request.json
        command = data['command']
        os.system(command)
        return jsonify({"status": "completed", "command": command})

    def register_worker():
        requests.post(f"{master_url}/register_worker", json={
            "worker_id": worker_id,
            "worker_url": f"http://{host}:{port}"
        })

    threading.Thread(target=register_worker).start()
    app.run(host=host, port=port)

@cli.command(name="vault-setup", help="Setup the vault for sensitive information.")
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Password for encryption')
def setup(password):
    setup_vault(password)
    click.echo("Vault has been set up.")



@cli.command(name="vault-encrypt", help="Encrypt files in the vault.")
@click.option('--password', prompt=True, hide_input=True, help='Password for encryption')
def encrypt(password):
    encrypt_vault(password)
    click.echo("Files in the vault have been encrypted.")


@cli.command(name="vault-decrypt", help="Decrypt files in the vault.")
@click.option('--password', prompt=True, hide_input=True, help='Password for decryption')
def decrypt(password):
    decrypt_vault(password)
    click.echo("Files in the vault have been decrypted.")


def load_jenkins_credentials_from_s3():
    key = load_jenkins_key()
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', **credentials)
        response = s3.get_object(Bucket=JENKINS_CREDENTIALS_BUCKET, Key=JENKINS_CREDENTIALS_FILE)
        encrypted_credentials = response['Body'].read()
        decrypted_credentials = decrypt_jenkins_data(encrypted_credentials, key)
        return json.loads(decrypted_credentials)
    except (NoCredentialsError, PartialCredentialsError) as e:
        click.echo(f"Error with AWS credentials: {e}")
    except ClientError as e:
        click.echo(f"Error loading credentials from S3: {e}")
        return None

def create_jenkins_job(job_name, jenkinsfile_path):
    jenkins_credentials = load_jenkins_credentials_from_s3()
    if not jenkins_credentials:
        click.echo("Failed to load Jenkins credentials.")
        return

    jenkins_url = jenkins_credentials['jenkins_url']
    username = jenkins_credentials['username']
    api_token = jenkins_credentials['api_token']

    with open(jenkinsfile_path, 'r') as file:
        jenkinsfile_content = file.read()

    job_config_xml = f"""<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job@2.40">
  <description></description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps@2.92">
    <script>{jenkinsfile_content}</script>
    <sandbox>true</sandbox>
  </definition>
  <triggers/>
  <disabled>false</disabled>
</flow-definition>"""

    job_url = f"{jenkins_url}/createItem?name={job_name}"
    headers = {'Content-Type': 'application/xml'}
    response = requests.post(job_url, data=job_config_xml, headers=headers, auth=(username, api_token))

    if response.status_code == 200:
        return f"Job '{job_name}' created successfully."
    elif response.status_code == 400:
        return f"Job '{job_name}' already exists. Updating the job."
    else:
        return f"Failed to create job '{job_name}'. Status code: {response.status_code}\n{response.text}"

def trigger_jenkins_job(job_name):
    credentials = load_jenkins_credentials_from_s3()
    if not credentials:
        click.echo("Failed to load Jenkins credentials.")
        return

    jenkins_url = credentials['jenkins_url']
    username = credentials['username']
    api_token = credentials['api_token']

    job_url = f"{jenkins_url}/job/{job_name}/build"
    response = requests.post(job_url, auth=(username, api_token))

    if response.status_code == 201:
        return f"Job '{job_name}' triggered successfully."
    else:
        return f"Failed to trigger job '{job_name}'. Status code: {response.status_code}\n{response.text}"

@cli.command(name="create-jenkins-job", help="Create a Jenkins job with a specified Jenkinsfile.")
@click.argument('job_name')
@click.argument('jenkinsfile_path', type=click.Path(exists=True))
def create_jenkins_job_command(job_name, jenkinsfile_path):
    result = create_jenkins_job(job_name, jenkinsfile_path)
    click.echo(result)

@cli.command(name="trigger-jenkins-job", help="Trigger a Jenkins job.")
@click.argument('job_name')
def trigger_jenkins_job_command(job_name):
    result = trigger_jenkins_job(job_name)
    click.echo(result)



# Function to generate and save the encryption key
def generate_k8s_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    click.echo("K8S encryption key generated and saved.")

# Load the encryption key
def load_k8s_key():
    return open(KEY_FILE, 'rb').read()


# Encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return encrypted

# Decrypt data
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data).decode()
    return decrypted

def load_kubeconfig_from_s3():
    credentials = load_aws_credentials()
    s3 = boto3.client('s3', **credentials)
    try:
        response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=S3_KUBECONFIG_KEY)
        kubeconfig_data = response['Body'].read().decode('utf-8')
        save_kubeconfig(kubeconfig_data)
        click.echo("Kubeconfig loaded from S3 successfully.")
    except ClientError as e:
        click.echo(f"Error loading kubeconfig from S3: {e}")



# Save kubeconfig locally
def save_kubeconfig(kubeconfig_data):
    ensure_private_folder()
    if not os.path.exists(os.path.dirname(KUBECONFIG_PATH)):
        os.makedirs(os.path.dirname(KUBECONFIG_PATH))
    with open(KUBECONFIG_PATH, 'w') as f:
        f.write(kubeconfig_data)
    os.chmod(KUBECONFIG_PATH, 0o600)


# Command to configure Kubernetes and save credentials


@cli.command()
@click.option('--k8s_vm_ip', prompt='K8S VM IP', help='The IP address of the K8S VM')
@click.option('--k8s_user', prompt='K8S User', help='The username for K8S')
@click.option('--k8s_key_path', prompt='K8S Key Path', help='The path to the key file for K8S')
@click.option('--k8s_token', prompt='K8S Token', help='The token for K8S authentication')
def configure_k8s(k8s_vm_ip, k8s_user, k8s_key_path, k8s_token):
    try:
        # Connect to the K8S VM and fetch the CA certificate
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(k8s_vm_ip, username=k8s_user, key_filename=k8s_key_path)
        sftp_client = ssh_client.open_sftp()
        ca_cert_path = "/etc/kubernetes/pki/ca.crt"
        ca_cert = sftp_client.file(ca_cert_path).read().decode()
        sftp_client.close()
        ssh_client.close()

        # Encode the CA certificate in base64
        ca_cert_base64 = base64.b64encode(ca_cert.encode()).decode()

        kubeconfig_data = f"""
apiVersion: v1
clusters:
- cluster:
    server: https://{k8s_vm_ip}:6443
    certificate-authority-data: {ca_cert_base64}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: {k8s_user}
  name: kubernetes
current-context: kubernetes
kind: Config
preferences: {{}}
users:
- name: {k8s_user}
  user:
    token: {k8s_token}
"""
        save_kubeconfig(kubeconfig_data)
        save_kubeconfig_to_s3(kubeconfig_data)
        click.echo("Kubernetes configuration completed and saved.")
    except Exception as e:
        click.echo(f"Error configuring Kubernetes: {e}")



# Command to run kubectl commands
def run_kubectl_command(command):
    try:
        # Load the kubeconfig from S3
        kubeconfig_data = load_kubeconfig_from_s3()
        with open(KUBECONFIG_PATH, 'w') as f:
            f.write(kubeconfig_data)

        config.load_kube_config(KUBECONFIG_PATH)
        api_instance = client.CoreV1Api()
        response = eval(f"api_instance.{command}")
        click.echo(response)
    except ApiException as e:
        click.echo(f"Exception when calling CoreV1Api: {e}")
    except Exception as e:
        click.echo(f"Error running kubectl command: {e}")


@cli.group()
def kubectl():
    """Kubernetes commands."""
    pass

@kubectl.command(name='get')
@click.argument('resource')
def get(resource):
    """Get Kubernetes resources."""
    command = f"get_{resource}()"
    run_kubectl_command(command)


def load_kubeconfig():
    """Load kubeconfig from S3 and save it locally."""
    credentials = load_aws_credentials()
    s3 = boto3.client('s3', **credentials)
    try:
        response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=KUBECONFIG_KEY)
        kubeconfig_data = response['Body'].read().decode('utf-8')
        with open(KUBECONFIG_PATH, 'w') as f:
            f.write(kubeconfig_data)
        os.chmod(KUBECONFIG_PATH, 0o600)
        click.echo("Kubeconfig loaded from S3 successfully.")
    except ClientError as e:
        click.echo(f"Error loading kubeconfig from S3: {e}")

# Generic handler to run kubectl commands
@click.command(name='kubectl', context_settings=dict(
    ignore_unknown_options=True,
    allow_extra_args=True,
))
@click.argument('kubectl_args', nargs=-1, type=click.UNPROCESSED)
def kubectl(kubectl_args):
    """Run any kubectl command."""
    load_kubeconfig()
    cmd = ['kubectl'] + list(kubectl_args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        click.echo(result.stdout)
    if result.stderr:
        click.echo(result.stderr)




# Function to create an S3 bucket
def create_s3_bucket(bucket_name, region=None):
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', **credentials)
        if region and region != 'us-east-1':
            s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': region})
        else:
            s3.create_bucket(Bucket=bucket_name)
        click.echo(f"Bucket {bucket_name} created successfully.")
    except ClientError as e:
        click.echo(f"Error creating bucket: {e}")

def save_kubeconfig(kubeconfig_data):
    ensure_private_folder()
    kubeconfig_dir = os.path.dirname(KUBECONFIG_PATH)
    if not os.path.exists(kubeconfig_dir):
        os.makedirs(kubeconfig_dir, mode=0o700, exist_ok=True)

    with open(KUBECONFIG_PATH, 'w') as f:
        f.write(kubeconfig_data)
    os.chmod(KUBECONFIG_PATH, 0o600)
#save
@cli.command(name="kubectl", help="Run a kubectl command.")
@click.argument('command')
def kubectl_command(command):
    run_kubectl_command(command)


def fetch_kubeconfig(k8s_vm_ip, k8s_user, k8s_key_path):
    key = paramiko.RSAKey.from_private_key_file(k8s_key_path)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=k8s_vm_ip, username=k8s_user, pkey=key)
    sftp = client.open_sftp()
    remote_kubeconfig_path = '/etc/kubernetes/admin.conf'
    kubeconfig_data = sftp.file(remote_kubeconfig_path).read().decode('utf-8')
    sftp.close()
    client.close()
    return kubeconfig_data

def configure_k8s(k8s_vm_ip, k8s_user, k8s_key_path):
    try:
        # Fetch the kubeconfig from the Kubernetes VM
        kubeconfig_data = fetch_kubeconfig(k8s_vm_ip, k8s_user, k8s_key_path)

        # Encrypt the kubeconfig data
        if not os.path.exists(KEY_FILE):
            generate_key()
        key = load_key()
        encrypted_kubeconfig = encrypt_data(kubeconfig_data, key)

        # Save the encrypted kubeconfig to S3
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', **credentials)
        s3.create_bucket(Bucket=S3_BUCKET_NAME)
        s3.put_object(Bucket=S3_BUCKET_NAME, Key=KUBECONFIG_KEY, Body=encrypted_kubeconfig)

        click.echo("Kubernetes configuration saved to S3 and encrypted successfully.")
    except Exception as e:
        click.echo(f"Error configuring Kubernetes: {e}")

def save_kubeconfig_to_s3(kubeconfig_data):
    credentials = load_aws_credentials()
    if not credentials:
        click.echo("No AWS credentials found. Please configure them first using 'dob configure-aws'.")
        return

    try:
        s3 = boto3.client('s3', **credentials)
        s3.put_object(Bucket=S3_BUCKET_NAME, Key=KUBECONFIG_KEY, Body=kubeconfig_data)
        click.echo("Kubeconfig saved to S3 successfully.")
    except ClientError as e:
        click.echo(f"Error saving kubeconfig to S3: {e}")

cli.add_command(kubectl)


if __name__ == '__main__':
    if not os.path.exists(KEY_FILE):
        generate_k8s_key()


    cli.add_command(configure_aws)
    cli.add_command(login)
    cli.add_command(create_ec2)
    cli.add_command(create_ec2_dob)
    cli.add_command(recreate_ec2)
    cli.add_command(view_version)
    cli.add_command(delete_ec2)
    cli.add_command(delete_object)
    cli.add_command(delete_bucket)
    cli.add_command(list_ec2_instances)
    cli.add_command(list_s3_buckets)
    cli.add_command(list_s3_objects)
    cli.add_command(create_s3_bucket_cli)
    cli.add_command(create_s3_bucket_dob)
    cli.add_command(setup_master)
    cli.add_command(delete_worker)
    cli.add_command(stop_worker)
    cli.add_command(list_workers)
    cli.add_command(assign_task)
    cli.add_command(create_worker)
    cli.add_command(configure_jenkins)
    cli.add_command(jenkins_job)
    cli.add_command(create_jenkins_job_command)
    cli.add_command(configure_k8s)
    cli.add_command(run_kubectl_command)
    cli.add_command(kubectl)
    cli()
    app.run(debug=True)
