#!/bin/bash
# VUL881 | Privilege Escalation | GCP IAM | Severity: CRITICAL | CVSS: 9.4
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Run with misconfigured service account allowing privilege escalation.

# Step 1: List all project-level IAM bindings
gcloud projects get-iam-policy {{PROJECT_ID}}

# Step 2: Remove primitive roles (owner, editor)
gcloud projects remove-iam-policy-binding {{PROJECT_ID}} \
  --member=serviceAccount:{{SA_EMAIL}} \
  --role=roles/owner

# Step 3: Disable service account key creation
gcloud resource-manager org-policies set-policy \
  --organization={{ORG_ID}} \
  disable-service-account-key-creation-policy.json

# Step 4: Enable Security Command Center
gcloud services enable securitycenter.googleapis.com