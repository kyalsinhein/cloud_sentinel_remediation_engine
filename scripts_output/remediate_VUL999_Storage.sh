#!/bin/bash
# VUL999 | Data Exposure | GCP Storage | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Storage with misconfigured bucket ACL allowing data tampering.

# Step 1: List current IAM policy bindings on the resource
gcloud storage buckets get-iam-policy gs://{{BUCKET_NAME}}

# Step 2: Remove the public/wildcard member binding
gcloud storage buckets remove-iam-policy-binding gs://{{BUCKET_NAME}} \
  --member=allUsers \
  --role={{ROLE}}

# Step 3: If this is a Cloud Run / Cloud Function service, also remove
# unauthenticated-invoker access
gcloud run services remove-iam-policy-binding {{SERVICE_NAME}} \
  --member=allUsers \
  --role=roles/run.invoker \
  --region={{REGION}}