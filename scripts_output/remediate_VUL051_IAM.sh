#!/bin/bash
# VUL051 | IAM Misconfiguration | AWS IAM | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS IAM role with pass-role privilege escalation.

# Step 1: Pull the full authorization snapshot for review
aws iam get-account-authorization-details > /tmp/iam-snapshot.json

# Step 2: Run IAM Access Analyzer to surface unused/external-facing permissions
aws accessanalyzer create-analyzer --analyzer-name {{ANALYZER_NAME}} --type ACCOUNT
aws accessanalyzer list-findings --analyzer-arn {{ANALYZER_ARN}}

# Step 3: Detach the misconfigured policy and reattach a scoped replacement
aws iam detach-role-policy --role-name {{ROLE_NAME}} --policy-arn {{POLICY_ARN}}
aws iam attach-role-policy --role-name {{ROLE_NAME}} --policy-arn {{SCOPED_POLICY_ARN}}