#!/bin/bash
# VUL491 | Code Injection | AWS Serverless | Severity: CRITICAL | CVSS: 9.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS Lambda with misconfigured environment variable allowing code injection.

# Step 1: Store the exposed secret in Secrets Manager
aws secretsmanager create-secret --name {{RESOURCE_NAME_VUL491}}-secret --secret-string '{{SECRET_VALUE}}'

# Step 2: Remove the plaintext value from the function's environment variables
aws lambda update-function-configuration --function-name {{RESOURCE_NAME_VUL491}} \
  --environment 'Variables={}'

# Step 3: Enable KMS encryption for any environment variables that remain
aws lambda update-function-configuration --function-name {{RESOURCE_NAME_VUL491}} \
  --kms-key-arn {{KMS_KEY_ARN}}

# Step 4: Restrict the function's resource-based policy
aws lambda get-policy --function-name {{RESOURCE_NAME_VUL491}}