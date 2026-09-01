#!/bin/bash
# VUL237 | Security Policy | AWS IAM | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS CloudFormation with no stack policy.

# Step 1: Enable Security Hub and a baseline standard
aws securityhub enable-security-hub --enable-default-standards

# Step 2: Create a preventative Service Control Policy
aws organizations create-policy --name {{SCP_NAME}} \
  --type SERVICE_CONTROL_POLICY --content file://{{SCP_FILE}}

# Step 3: Attach the SCP to the relevant organizational unit
aws organizations attach-policy --policy-id {{POLICY_ID}} --target-id {{OU_ID}}