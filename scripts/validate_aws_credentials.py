import boto3
import os
import sys
from botocore.exceptions import NoCredentialsError, ClientError

def validate_aws_credentials(credentials, account_id):
    try:
        sts_client = boto3.client("sts",
              aws_access_key_id=credentials["aws_access_key_id"],
              aws_secret_access_key=credentials["aws_secret_access_key"],
              aws_session_token=credentials.get("aws_session_token"))
    except (ClientError, NoCredentialsError, KeyError):
        return False

    # Get the caller identity from the STS client
    try:
        caller_identity = sts_client.get_caller_identity()
    except (ClientError, NoCredentialsError):
        return False

    # Check if the caller account ID matches the specified account ID
    if caller_identity["Account"] == account_id:
        return True
    else:
        return False

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
    if not valid:
        print(f"The provided AWS credentials are not valid for the specified AWS account ID: {aws_account_id}")
        sys.exit(1)
    else:
        sys.exit(0)
