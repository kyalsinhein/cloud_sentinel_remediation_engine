#!/bin/bash
# VUL521 | Denial of Service | GCP Serverless | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Functions with misconfigured timeout allowing resource exhaustion.

# Step 1: Store the exposed secret in Secret Manager
gcloud secrets create {{RESOURCE_NAME_VUL521}}-secret --data-file={{SECRET_FILE}}

# Step 2: Mount it as a secret instead of a plaintext env var
gcloud functions deploy {{RESOURCE_NAME_VUL521}} --set-secrets='{{ENV_VAR}}={{RESOURCE_NAME_VUL521}}-secret:latest'

# Step 3: Restrict who can invoke the function
gcloud functions remove-iam-policy-binding {{RESOURCE_NAME_VUL521}} \
  --member=allUsers --role=roles/cloudfunctions.invoker