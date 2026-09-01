#!/bin/bash
# VUL373 | Encryption | AWS Storage | Severity: MEDIUM | CVSS: 6.0
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS S3 bucket with misconfigured encryption rules exposing data.

# ── Step 1: Enable versioning ────────────────────────────────────────────
aws s3api put-bucket-versioning \
  --bucket {{RESOURCE_NAME_VUL373}} \
  --versioning-configuration Status=Enabled

# ── Step 2: Enable MFA Delete (requires root MFA device) ─────────────────
aws s3api put-bucket-versioning \
  --bucket {{RESOURCE_NAME_VUL373}} \
  --mfa "{{MFA_SERIAL}} {{MFA_TOKEN}}" \
  --versioning-configuration MFADelete=Enabled,Status=Enabled

# ── Step 3: Apply lifecycle policy to expire old versions ────────────────
aws s3api put-bucket-lifecycle-configuration \
  --bucket {{RESOURCE_NAME_VUL373}} \
  --lifecycle-configuration file://s3-lifecycle-policy.json