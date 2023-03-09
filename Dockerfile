FROM hashicorp/terraform:light
RUN apk --no-cache add python3 py3-pip jq curl
RUN pip3 install awscli boto3

WORKDIR /workspace
COPY ./scripts/kms /workspace/scripts/kms
