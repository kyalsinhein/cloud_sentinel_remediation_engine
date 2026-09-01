#!/bin/bash
# VUL855 | Authentication | AWS General | Severity: CRITICAL | CVSS: 9.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS ElastiCache with misconfigured Redis AUTH allowing unauthorized access.

# Step 1: Delete root account access keys
aws iam list-access-keys --user-name root
aws iam update-access-key \
  --access-key-id {{ACCESS_KEY_ID}} \
  --status Inactive
aws iam delete-access-key \
  --access-key-id {{ACCESS_KEY_ID}}

# Step 2: Enforce MFA for all IAM users
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols --require-numbers \
  --require-uppercase-characters \
  --max-password-age 90

# Step 3: Enable GuardDuty for anomaly detection
aws guardduty create-detector --enable

# Step 4: Rotate all active access keys
aws iam list-users --query Users[*].UserName --output text | \
  xargs -I{} aws iam list-access-keys --user-name {}