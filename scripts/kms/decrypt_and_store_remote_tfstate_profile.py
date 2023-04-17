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
    get_and_decrypt_keypair(aws_account_id)
