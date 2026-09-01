#!/bin/bash
# VUL077 | Access Control | GCP Logging | Severity: HIGH | CVSS: 8.8
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Monitoring with public dashboard.

# Step 1: List all IAM bindings on the project
gcloud projects get-iam-policy {{PROJECT_ID}} --format=json

# Step 2: Remove primitive Editor/Owner role
gcloud projects remove-iam-policy-binding {{PROJECT_ID}} \
  --member=serviceAccount:{{SA_EMAIL}} \
  --role=roles/editor

# Step 3: Grant least-privilege custom role
gcloud projects add-iam-policy-binding {{PROJECT_ID}} \
  --member=serviceAccount:{{SA_EMAIL}} \
  --role=roles/viewer

# Step 4: Verify final bindings
gcloud projects get-iam-policy {{PROJECT_ID}} \
  --flatten=bindings --format=table