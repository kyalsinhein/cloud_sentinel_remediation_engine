#!/bin/bash
# VUL257 | Encryption | GCP Serverless | Severity: MEDIUM | CVSS: 6.0
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Functions with no environment variable encryption.

# Step 1: Store the exposed secret in Secret Manager
gcloud secrets create {{RESOURCE_NAME_VUL257}}-secret --data-file={{SECRET_FILE}}

# Step 2: Mount it as a secret instead of a plaintext env var
gcloud functions deploy {{RESOURCE_NAME_VUL257}} --set-secrets='{{ENV_VAR}}={{RESOURCE_NAME_VUL257}}-secret:latest'

# Step 3: Restrict who can invoke the function
gcloud functions remove-iam-policy-binding {{RESOURCE_NAME_VUL257}} \
  --member=allUsers --role=roles/cloudfunctions.invoker