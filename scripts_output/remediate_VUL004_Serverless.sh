#!/bin/bash
# VUL004 | Data Exposure | AWS Serverless | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Unencrypted AWS Lambda environment variables leaking API keys.

# Step 1: Store the exposed secret in Secrets Manager
aws secretsmanager create-secret --name {{RESOURCE_NAME_VUL004}}-secret --secret-string '{{SECRET_VALUE}}'

# Step 2: Remove the plaintext value from the function's environment variables
aws lambda update-function-configuration --function-name {{RESOURCE_NAME_VUL004}} \
  --environment 'Variables={}'

# Step 3: Enable KMS encryption for any environment variables that remain
aws lambda update-function-configuration --function-name {{RESOURCE_NAME_VUL004}} \
  --kms-key-arn {{KMS_KEY_ARN}}

# Step 4: Restrict the function's resource-based policy
aws lambda get-policy --function-name {{RESOURCE_NAME_VUL004}}