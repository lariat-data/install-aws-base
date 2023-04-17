FROM --platform=linux/amd64 hashicorp/terraform:latest
RUN apk --no-cache add python3 python3-dev py3-pip jq curl
RUN pip3 install awscli boto3

WORKDIR /workspace
COPY ./scripts/kms /workspace/scripts/kms
