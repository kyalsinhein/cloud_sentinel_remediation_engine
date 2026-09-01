#!/bin/bash
# VUL573 | Data Exfiltration | AWS General | Severity: HIGH | CVSS: 7.1
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS SNS with misconfigured subscription endpoint allowing data exfiltration.

# Step 1: Enable GuardDuty (detects exfiltration attempts)
aws guardduty create-detector --enable

# Step 2: Block public S3 access account-wide
aws s3control put-public-access-block \
  --account-id {{ACCOUNT_ID}} \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Step 3: Enable Macie for sensitive data monitoring
aws macie2 enable-macie

# Step 4: Apply SCP to deny s3:GetObject from outside org
aws organizations create-policy \
  --name DenyExternalS3Access \
  --type SERVICE_CONTROL_POLICY \
  --content file://deny-external-s3.json