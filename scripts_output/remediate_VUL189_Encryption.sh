#!/bin/bash
# VUL189 | Encryption | AWS Encryption | Severity: MEDIUM | CVSS: 6.0
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS CodeBuild with no artifact encryption.

# ── Step 1: Enable automatic key rotation ────────────────────────────────
aws kms enable-key-rotation \
  --key-id {{RESOURCE_NAME_VUL189}}

# ── Step 2: Verify rotation status ──────────────────────────────────────
aws kms get-key-rotation-status \
  --key-id {{RESOURCE_NAME_VUL189}}