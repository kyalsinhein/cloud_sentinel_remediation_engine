#!/bin/bash
# VUL161 | IAM Misconfiguration | GCP IAM | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Build with no service account restrictions.

# Step 1: Export the current IAM policy for review
gcloud projects get-iam-policy {{PROJECT_ID}} --format=json > /tmp/iam-policy.json

# Step 2: Remove the overly broad binding
gcloud projects remove-iam-policy-binding {{PROJECT_ID}} \
  --member={{MEMBER}} --role={{CURRENT_ROLE}}

# Step 3: Grant a scoped custom role instead
gcloud projects add-iam-policy-binding {{PROJECT_ID}} \
  --member={{MEMBER}} --role={{SCOPED_ROLE}}