#!/bin/bash
# VUL1167 | Access Control | AWS Storage | Severity: HIGH | CVSS: 8.8
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS S3 bucket with misconfigured notification policy allowing unauthorized actions.

# ── Step 1: Block all public access ──────────────────────────────────────
aws s3api put-public-access-block \
  --bucket {{RESOURCE_NAME_VUL1167}} \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,\
  BlockPublicPolicy=true,RestrictPublicBuckets=true

# ── Step 2: Enable AES-256 server-side encryption ────────────────────────
aws s3api put-bucket-encryption \
  --bucket {{RESOURCE_NAME_VUL1167}} \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# ── Step 3: Enable versioning ────────────────────────────────────────────
aws s3api put-bucket-versioning \
  --bucket {{RESOURCE_NAME_VUL1167}} \
  --versioning-configuration Status=Enabled

# ── Step 4: Enable S3 access logging ─────────────────────────────────────
aws s3api put-bucket-logging \
  --bucket {{RESOURCE_NAME_VUL1167}} \
  --bucket-logging-status \
  '{"LoggingEnabled":{"TargetBucket":"{{AUDIT_LOG_BUCKET}}","TargetPrefix":"s3-logs/"}}'

# ── Step 5: Verify configuration ─────────────────────────────────────────
aws s3api get-bucket-encryption --bucket {{RESOURCE_NAME_VUL1167}}
aws s3api get-public-access-block --bucket {{RESOURCE_NAME_VUL1167}}