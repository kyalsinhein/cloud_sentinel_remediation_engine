#!/bin/bash
# VUL195 | Encryption | AWS Encryption | Severity: MEDIUM | CVSS: 6.0
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS ElastiCache with no encryption in transit.

# ── Step 1: Enable automatic key rotation ────────────────────────────────
aws kms enable-key-rotation \
  --key-id {{RESOURCE_NAME_VUL195}}

# ── Step 2: Verify rotation status ──────────────────────────────────────
aws kms get-key-rotation-status \
  --key-id {{RESOURCE_NAME_VUL195}}