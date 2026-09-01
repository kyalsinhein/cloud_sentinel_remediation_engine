#!/bin/bash
# VUL1085 | Data Exposure | AWS General | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS SNS with misconfigured message attributes exposing sensitive data.

# Step 1: Block all S3 public access
aws s3api put-public-access-block \
  --bucket {{BUCKET_NAME}} \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Step 2: Enable S3 server-side encryption
aws s3api put-bucket-encryption \
  --bucket {{BUCKET_NAME}} \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# Step 3: Enable CloudTrail logging
aws cloudtrail create-trail \
  --name DataAuditTrail \
  --s3-bucket-name {{LOG_BUCKET}} \
  --is-multi-region-trail
aws cloudtrail start-logging --name DataAuditTrail

# Step 4: Enable Macie for sensitive data discovery
aws macie2 enable-macie
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --s3-job-definition '{"bucketDefinitions":[{"accountId":"{{ACCOUNT_ID}}","buckets":["{{BUCKET_NAME}}"]}]}'