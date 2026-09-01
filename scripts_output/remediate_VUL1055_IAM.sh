#!/bin/bash
# VUL1055 | Access Control | AWS IAM | Severity: HIGH | CVSS: 8.8
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS ElastiCache with misconfigured Memcached access allowing unauthorized connections.

# Step 1: List all policies with wildcard actions
aws iam list-policies --scope Local --output table

# Step 2: Identify and remove wildcard (*) permissions
aws iam get-policy-version \
  --policy-arn {{POLICY_ARN}} \
  --version-id v1 --output json

# Step 3: Create restricted replacement policy
aws iam create-policy-version \
  --policy-arn {{POLICY_ARN}} \
  --policy-document file://restricted-policy.json \
  --set-as-default

# Step 4: Enable MFA enforcement via SCP
aws organizations create-policy \
  --name EnforceMFA \
  --type SERVICE_CONTROL_POLICY \
  --content file://enforce-mfa-scp.json

# Step 5: Audit all IAM users for excess permissions
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d