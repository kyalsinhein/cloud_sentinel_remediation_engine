#!/bin/bash
# VUL561 | Code Injection | AWS AppSec | Severity: CRITICAL | CVSS: 9.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS CodeBuild with misconfigured buildspec allowing code injection.

# Step 1: Attach WAF to API Gateway / ALB
aws wafv2 associate-web-acl \
  --web-acl-arn {{WAF_ACL_ARN}} \
  --resource-arn {{API_GATEWAY_ARN}}

# Step 2: Enable AWS managed rule groups (SQL injection, XSS)
# Add to WAF ACL rules: AWSManagedRulesSQLiRuleSet, AWSManagedRulesCommonRuleSet

# Step 3: Restrict Lambda execution role
aws iam update-role \
  --role-name {{LAMBDA_ROLE}} \
  --description Least-privilege Lambda role

# Step 4: Enable Lambda code signing
aws lambda put-function-code-signing-config \
  --function-name {{FUNCTION_NAME}} \
  --code-signing-config-arn {{CODE_SIGNING_ARN}}