#!/bin/bash
# VUL041 | Access Control | AWS IAM | Severity: HIGH | CVSS: 8.8
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS SQS queue with open permissions.

# Step 1: Retrieve the current bucket policy to find the wildcard statement
aws s3api get-bucket-policy --bucket {{BUCKET_NAME}} --output text

# Step 2: Replace the wildcard Principal with the specific principal(s)/
# role ARN(s) that legitimately need access, then apply the corrected policy
aws s3api put-bucket-policy \
  --bucket {{BUCKET_NAME}} \
  --policy file://{{SAFE_POLICY_JSON}}

# Step 3: Block public access at the bucket level as defense-in-depth
aws s3api put-public-access-block \
  --bucket {{BUCKET_NAME}} \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true