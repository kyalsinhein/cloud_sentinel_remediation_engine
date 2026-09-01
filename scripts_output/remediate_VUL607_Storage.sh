#!/bin/bash
# VUL607 | Data Exfiltration | AWS Storage | Severity: HIGH | CVSS: 7.1
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS S3 bucket with misconfigured CORS policy allowing data exfiltration.

# ── Step 1: Block all public access ──────────────────────────────────────
aws s3api put-public-access-block \
  --bucket {{RESOURCE_NAME_VUL607}} \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,\
  BlockPublicPolicy=true,RestrictPublicBuckets=true

# ── Step 2: Enable AES-256 server-side encryption ────────────────────────
aws s3api put-bucket-encryption \
  --bucket {{RESOURCE_NAME_VUL607}} \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# ── Step 3: Enable versioning ────────────────────────────────────────────
aws s3api put-bucket-versioning \
  --bucket {{RESOURCE_NAME_VUL607}} \
  --versioning-configuration Status=Enabled

# ── Step 4: Enable S3 access logging ─────────────────────────────────────
aws s3api put-bucket-logging \
  --bucket {{RESOURCE_NAME_VUL607}} \
  --bucket-logging-status \
  '{"LoggingEnabled":{"TargetBucket":"{{AUDIT_LOG_BUCKET}}","TargetPrefix":"s3-logs/"}}'

# ── Step 5: Verify configuration ─────────────────────────────────────────
aws s3api get-bucket-encryption --bucket {{RESOURCE_NAME_VUL607}}
aws s3api get-public-access-block --bucket {{RESOURCE_NAME_VUL607}}