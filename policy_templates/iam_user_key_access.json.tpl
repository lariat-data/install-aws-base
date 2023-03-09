{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "1",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "$kms_key_arn"
    },
    {
      "Sid": "2",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::lariat-customer-installation-tfstate/$customer_account_id/testkeys/*"
    }
  ]
}
