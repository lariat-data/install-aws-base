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

def allow_caller_identity_role_access(account_id, kms_key_arn):
    sts = boto3.client('sts')
    arn = sts.get_caller_identity()["Arn"]

    with open("policy_templates/iam_user_key_access.json.tpl", "r") as f:
        src = Template(f.read())
        result = src.substitute({
            "customer_account_id": account_id,
            "kms_key_arn": kms_key_arn
        })

def download_s3_keys_enc(customer_account_id):
    session = boto3.Session()
    s3_client = session.client('s3')
    s3_client.download_file(LARIAT_TERRAFORM_BUCKET_NAME, f"{customer_account_id}/testkeys/{LARIAT_KEYS_ENC_FILE}", LARIAT_KEYS_ENC_FILE)

def decrypt_s3_keys_enc(fileloc, customer_account_id):
    # Define the AWS KMS client
    kms_client = boto3.client('kms')

    with open(fileloc, "rb") as encrypted_file:
        encrypted_text = encrypted_file.read()
        response = kms_client.decrypt(
            CiphertextBlob=encrypted_text,
            EncryptionContext={'user': 'terraform-user-' + customer_account_id}
        )

        decrypted_text = response['Plaintext']
        with open(LARIAT_KEYS_FILE, "wb") as decrypted_file:
            decrypted_file.write(decrypted_text)

def get_and_decrypt_keypair(customer_account_id):
    download_s3_keys_enc(customer_account_id)
    decrypt_s3_keys_enc(LARIAT_KEYS_ENC_FILE, customer_account_id)

    # Open the file containing the output
    with open(LARIAT_KEYS_FILE, 'r') as f:
        output = json.load(f)

    # Parse the output to extract the access key ID and secret
    access_key_id = output["aws_access_key_id"]
    access_key_secret = output["aws_secret_access_key"]

    # Create a client for the STS service
    sts_client = boto3.client('sts',
                            aws_access_key_id=access_key_id,
                            aws_secret_access_key=access_key_secret,
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

    os.remove(LARIAT_KEYS_FILE)
    os.remove(LARIAT_KEYS_ENC_FILE)

    print(json.dumps(temp_creds, indent=4))

if __name__ == '__main__':
    aws_account_id = sys.argv[1]
    get_and_decrypt_keypair(aws_account_id)
