#!/bin/bash
# VUL631 | Data Loss | AWS IAM | Severity: HIGH | CVSS: 7.2
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS SNS with misconfigured delivery retry policy allowing message loss.

# Step 1: Enable S3 versioning on the affected bucket
aws s3api put-bucket-versioning \
  --bucket {{BUCKET_NAME}} --versioning-configuration Status=Enabled

# Step 2: Enable AWS Backup for the resource
aws backup create-backup-plan --backup-plan file://backup-plan.json

# Step 3: Enable deletion protection (RDS/DynamoDB)
aws rds modify-db-instance \
  --db-instance-identifier {{DB_ID}} --deletion-protection