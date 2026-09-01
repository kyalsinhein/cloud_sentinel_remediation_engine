#!/bin/bash
# VUL801 | Privilege Escalation | AWS IAM | Severity: CRITICAL | CVSS: 9.4
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS ECS with misconfigured IAM role allowing privilege escalation.

# ── Step 1: List all locally-managed policies ─────────────────────────────
aws iam list-policies --scope Local \
  --query 'Policies[*].[PolicyName,Arn]' --output table

# ── Step 2: Retrieve current policy document ──────────────────────────────
aws iam get-policy-version \
  --policy-arn {{RESOURCE_NAME_VUL801}} \
  --version-id v1 --output json

# ── Step 3: Create restricted replacement policy ──────────────────────────
# Edit restricted-policy.json to remove all wildcard (*) Actions/Resources
aws iam create-policy-version \
  --policy-arn {{RESOURCE_NAME_VUL801}} \
  --policy-document file://restricted-policy.json \
  --set-as-default

# ── Step 4: Delete the old wildcard version ───────────────────────────────
aws iam delete-policy-version \
  --policy-arn {{RESOURCE_NAME_VUL801}} \
  --version-id v1

# ── Step 5: Enforce MFA for all users attached to this policy ────────────
aws iam list-entities-for-policy \
  --policy-arn {{RESOURCE_NAME_VUL801}} \
  --entity-filter User --output table