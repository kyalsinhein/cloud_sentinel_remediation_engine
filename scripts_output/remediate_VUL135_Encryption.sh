#!/bin/bash
# VUL135 | Encryption | AWS Encryption | Severity: MEDIUM | CVSS: 6.0
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS Redshift with no encryption.

# ── Step 1: Enable automatic key rotation ────────────────────────────────
aws kms enable-key-rotation \
  --key-id {{RESOURCE_NAME_VUL135}}

# ── Step 2: Verify rotation status ──────────────────────────────────────
aws kms get-key-rotation-status \
  --key-id {{RESOURCE_NAME_VUL135}}