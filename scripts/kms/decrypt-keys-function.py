import boto3
import json
import os
import sys
from datetime import datetime

def get_and_decrypt_keypair(LARIAT_CUSTOMER_PROFILE, LARIAT_CUSTOMER_ACCOUNT_ID):

    LARIAT_TF_VARS_FILE = "terraform.tfvars"
    LARIAT_TF_VARS_ENC_FILE = "keys.enc"
    LARIAT_TERRAFORM_BUCKET_NAME = "lariat-customer-installation-tfstate"
    
    # Open session from customer's profile
    session = boto3.Session(profile_name=LARIAT_CUSTOMER_PROFILE)
    s3_client = session.client('s3')
    s3_client.download_file(LARIAT_TERRAFORM_BUCKET_NAME, f"{LARIAT_CUSTOMER_ACCOUNT_ID}/testkeys/{LARIAT_TF_VARS_ENC_FILE}", LARIAT_TF_VARS_ENC_FILE)

    # Define the AWS KMS client
    kms_client = session.client('kms')

    # Decrypt the credentials file from Lariat account
    with open(LARIAT_TF_VARS_ENC_FILE, "rb") as encrypted_file:
        encrypted_text = encrypted_file.read()
        response = kms_client.decrypt(
            CiphertextBlob=encrypted_text,
            EncryptionContext={'user': 'terraform-user-' + LARIAT_CUSTOMER_ACCOUNT_ID}
        )
        decrypted_text = response['Plaintext']
        with open(LARIAT_TF_VARS_FILE, "wb") as decrypted_file:
            decrypted_file.write(decrypted_text)

    # Display the content of the decrypted file
    with open(LARIAT_TF_VARS_FILE, "r") as file:
            content = file.read().strip()
    
    # Open the file containing the output
    with open(LARIAT_TF_VARS_FILE, 'r') as f:
        output = f.read()

    # Extract values for access_key_id and access_key_secret
    data = json.loads(output)

    access_key_id = data['aws_access_key_id']
    access_key_secret = data['aws_secret_access_key']
    
    # Create a client for the STS service
    sts_client = boto3.client('sts',
                            aws_access_key_id=access_key_id,
                            aws_secret_access_key=access_key_secret,
                            region_name='us-east-2'
                            )

    # Assume the cross-account role
    CROSS_ACCOUNT_ROLE_ARN = "arn:aws:iam::358681817243:role/lariat-iam-terraform-cross-account-access-role-" + LARIAT_CUSTOMER_ACCOUNT_ID
    CROSS_ACCOUNT_ROLE_SESSION_NAME = "terraform-s3-session-" + LARIAT_CUSTOMER_ACCOUNT_ID
    response = sts_client.assume_role(
        RoleArn=CROSS_ACCOUNT_ROLE_ARN,
        RoleSessionName=CROSS_ACCOUNT_ROLE_SESSION_NAME
    )

    # Extract the temp credentials from the assumed role
    temp_creds = response['Credentials']

    # Convert the datetime object to string 
    temp_creds['Expiration'] = temp_creds['Expiration'].strftime('%Y-%m-%dT%H:%M:%SZ')
    temp_creds['Expiration'] = str(temp_creds['Expiration'])  

    output_str = json.dumps(temp_creds)
    data = json.loads(output_str)

    temp_access_key_id = data['AccessKeyId']
    temp_access_key_secret = data['SecretAccessKey']
    temp_session_token = data['SessionToken']

    os.remove(LARIAT_TF_VARS_FILE)
    os.remove(LARIAT_TF_VARS_ENC_FILE)

    return temp_access_key_id, temp_access_key_secret, temp_session_token


# Get the action argument
if len(sys.argv) > 1:
    customer_profile = sys.argv[1]
else:
    print("Error: No action specified")
    sys.exit(1)

# Get the account ID argument
if len(sys.argv) > 2:
    account_id = sys.argv[2]
else:
    print("Error: No account ID specified")
    sys.exit(1)

print(get_and_decrypt_keypair(customer_profile, account_id))
