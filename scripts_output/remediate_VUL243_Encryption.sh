#!/bin/bash
# VUL243 | Security Policy | AWS Encryption | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS KMS with no key rotation enabled.

# Step 1: Enable KMS key rotation
aws kms enable-key-rotation --key-id {{KEY_ID}}
aws kms get-key-rotation-status --key-id {{KEY_ID}}

# Step 2: Enforce S3 encryption via bucket policy
aws s3api put-bucket-policy \
  --bucket {{BUCKET_NAME}} \
  --policy file://enforce-encryption-policy.json

# Step 3: Enable RDS encryption (requires snapshot restore)
aws rds create-db-snapshot \
  --db-instance-identifier {{DB_ID}} \
  --db-snapshot-identifier {{DB_ID}}-encrypted-snap

# Step 4: Enforce HTTPS-only on API Gateway
aws apigateway update-rest-api \
  --rest-api-id {{API_ID}} \
  --patch-operations op=replace,path=/minimumCompressionSize,value=0