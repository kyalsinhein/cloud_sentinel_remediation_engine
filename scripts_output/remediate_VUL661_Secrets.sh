#!/bin/bash
# VUL661 | Data Exposure | AWS Secrets | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS CodeBuild with misconfigured environment variables exposing secrets.

# Step 1: Rotate the exposed secret immediately
aws secretsmanager rotate-secret --secret-id {{RESOURCE_NAME_VUL661}}

# Step 2: Enable automatic rotation going forward
aws secretsmanager rotate-secret --secret-id {{RESOURCE_NAME_VUL661}} \
  --rotation-lambda-arn {{ROTATION_LAMBDA_ARN}} \
  --rotation-rules AutomaticallyAfterDays=30

# Step 3: Restrict IAM access to the secret to only what needs it
aws secretsmanager get-resource-policy --secret-id {{RESOURCE_NAME_VUL661}}