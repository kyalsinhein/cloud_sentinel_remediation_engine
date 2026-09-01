#!/bin/bash
# VUL463 | Data Exposure | GCP General | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Spanner with misconfigured table schema allowing data tampering.

# Step 1: Remove public access from bucket
gsutil iam ch -d allUsers:objectViewer gs://{{BUCKET_NAME}}
gsutil iam ch -d allAuthenticatedUsers:objectViewer gs://{{BUCKET_NAME}}

# Step 2: Enable uniform bucket-level access
gsutil uniformbucketlevelaccess set on gs://{{BUCKET_NAME}}

# Step 3: Enable Cloud Audit Logs
gcloud projects set-iam-policy {{PROJECT_ID}} audit-policy.json

# Step 4: Enable DLP for sensitive data scanning
gcloud services enable dlp.googleapis.com