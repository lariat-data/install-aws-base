import boto3
import json
import os
import sys
from datetime import datetime
from string import Template

LARIAT_KEYS_FILE = "keys.json"
LARIAT_KEYS_ENC_FILE = "keys.enc"
LARIAT_TERRAFORM_BUCKET_NAME = "lariat-customer-installation-tfstate"
CROSS_ACCOUNT_ROLE_BASE_ARN = "arn:aws:iam::358681817243:role/lariat-iam-terraform-cross-account-access-role"

def validate_aws_credentials(credentials, account_id):
    try:
        sts_client = boto3.client("sts",
                                  aws_access_key_id=credentials["aws_access_key_id"],
                                  aws_secret_access_key=credentials["aws_secret_access_key"],
                                  aws_session_token=credentials.get("aws_session_token"))
    except (ClientError, KeyError):
        return False

    # Get the caller identity from the STS client
    try:
        caller_identity = sts_client.get_caller_identity()
    except ClientError:
        return False

    # Check if the caller account ID matches the specified account ID
    if caller_identity["Account"] == account_id:
        return True
    else:
        return False

def get_and_decrypt_keypair(customer_account_id):
    # Create a client for the STS service
    sts_client = boto3.client('sts',
                            aws_access_key_id=os.environ["LARIAT_TMP_AWS_ACCESS_KEY_ID"],
                            aws_secret_access_key=os.environ["LARIAT_TMP_AWS_SECRET_ACCESS_KEY"],
                            region_name='us-east-2'
        )

    # Assume the cross-account role
    role_arn = f"{CROSS_ACCOUNT_ROLE_BASE_ARN}-{customer_account_id}"
    session_name = "terraform-s3-session-" + customer_account_id
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name
    )

    # Extract the temp credentials from the assumed role
    temp_creds = response['Credentials']

    # Convert the datetime object to string
    temp_creds['Expiration'] = temp_creds['Expiration'].strftime('%Y-%m-%dT%H:%M:%SZ')
    temp_creds['Expiration'] = str(temp_creds['Expiration'])

    print(json.dumps(temp_creds, indent=4))

if __name__ == '__main__':
    aws_account_id = sys.argv[1]

    aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    aws_session_token = os.getenv("AWS_SESSION_TOKEN")
    credentials = {
        "aws_access_key_id": aws_access_key_id,
        "aws_secret_access_key": aws_secret_access_key,
    }

    # Add the session token to the credentials dictionary if it exists
    if aws_session_token:
        credentials["aws_session_token"] = aws_session_token

    valid = validate_aws_credentials(credentials, aws_account_id)
    if valid:
        print(f"Successfully validated credentials for AWS account ID {aws_account_id}")
    else:
        sys.exit(f"The provided AWS credentials are not valid for the specified AWS account ID: {aws_account_id}")

    get_and_decrypt_keypair(aws_account_id)
