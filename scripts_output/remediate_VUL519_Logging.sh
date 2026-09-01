#!/bin/bash
# VUL519 | Data Exposure | AWS Logging | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS CloudTrail with misconfigured encryption allowing log exposure.

# ── Step 1: Create CloudTrail ────────────────────────────────────────────
aws cloudtrail create-trail \
  --name {{RESOURCE_NAME_VUL519}} \
  --s3-bucket-name {{CLOUDTRAIL_BUCKET}} \
  --is-multi-region-trail \
  --enable-log-file-validation

# ── Step 2: Start logging ─────────────────────────────────────────────────
aws cloudtrail start-logging --name {{RESOURCE_NAME_VUL519}}

# ── Step 3: Verify trail is active ───────────────────────────────────────
aws cloudtrail get-trail-status --name {{RESOURCE_NAME_VUL519}}