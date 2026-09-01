#!/bin/bash
# VUL099 | Data Protection | AWS Storage | Severity: MEDIUM | CVSS: 6.9
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS S3 bucket with no MFA delete enabled.

# ── Step 1: Enable versioning ────────────────────────────────────────────
aws s3api put-bucket-versioning \
  --bucket {{RESOURCE_NAME_VUL099}} \
  --versioning-configuration Status=Enabled

# ── Step 2: Enable MFA Delete (requires root MFA device) ─────────────────
aws s3api put-bucket-versioning \
  --bucket {{RESOURCE_NAME_VUL099}} \
  --mfa "{{MFA_SERIAL}} {{MFA_TOKEN}}" \
  --versioning-configuration MFADelete=Enabled,Status=Enabled

# ── Step 3: Apply lifecycle policy to expire old versions ────────────────
aws s3api put-bucket-lifecycle-configuration \
  --bucket {{RESOURCE_NAME_VUL099}} \
  --lifecycle-configuration file://s3-lifecycle-policy.json