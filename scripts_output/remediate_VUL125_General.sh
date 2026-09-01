#!/bin/bash
# VUL125 | Authentication | GCP General | Severity: CRITICAL | CVSS: 9.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Service Account with no key rotation.

# Step 1: List service account keys older than 90 days
gcloud iam service-accounts keys list \
  --iam-account={{SA_EMAIL}} --managed-by=user

# Step 2: Delete the exposed/legacy key
gcloud iam service-accounts keys delete {{KEY_ID}} \
  --iam-account={{SA_EMAIL}}

# Step 3: Enforce org-wide 2-Step Verification
gcloud resource-manager org-policies set-policy \
  --organization={{ORG_ID}} \
  enforce-2sv-policy.json

# Step 4: Enable Identity-Aware Proxy for sensitive services
gcloud services enable iap.googleapis.com