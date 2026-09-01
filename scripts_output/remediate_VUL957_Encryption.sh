#!/bin/bash
# VUL957 | Encryption | GCP Encryption | Severity: MEDIUM | CVSS: 6.0
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud VPN with misconfigured IKE version allowing weak encryption.

# Step 1: Set automatic KMS key rotation (90 days)
gcloud kms keys update {{KEY_NAME}} \
  --keyring={{KEYRING}} --location={{LOCATION}} \
  --rotation-period=90d --next-rotation-time=+p90d

# Step 2: Enforce customer-managed encryption keys on the bucket
gcloud storage buckets update gs://{{BUCKET_NAME}} \
  --default-encryption-key={{KMS_KEY_RESOURCE}}

# Step 3: Verify encryption configuration
gcloud kms keys describe {{KEY_NAME}} \
  --keyring={{KEYRING}} --location={{LOCATION}}