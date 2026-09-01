#!/bin/bash
# VUL693 | Data Exposure | GCP Secrets | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Run with misconfigured environment variable exposing secrets.

# Step 1: Add a new secret version
gcloud secrets versions add {{RESOURCE_NAME_VUL693}} --data-file={{NEW_SECRET_FILE}}

# Step 2: Disable the exposed old version
gcloud secrets versions disable {{OLD_VERSION_ID}} --secret={{RESOURCE_NAME_VUL693}}

# Step 3: Restrict IAM access to the secret
gcloud secrets get-iam-policy {{RESOURCE_NAME_VUL693}}