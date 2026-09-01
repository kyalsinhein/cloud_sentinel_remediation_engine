#!/bin/bash
# VUL003 | IAM Misconfiguration | GCP Serverless | Severity: MEDIUM | CVSS: 6.9
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Function with unauthenticated HTTP trigger.

# Step 1: Store the exposed secret in Secret Manager
gcloud secrets create {{RESOURCE_NAME_VUL003}}-secret --data-file={{SECRET_FILE}}

# Step 2: Mount it as a secret instead of a plaintext env var
gcloud functions deploy {{RESOURCE_NAME_VUL003}} --set-secrets='{{ENV_VAR}}={{RESOURCE_NAME_VUL003}}-secret:latest'

# Step 3: Restrict who can invoke the function
gcloud functions remove-iam-policy-binding {{RESOURCE_NAME_VUL003}} \
  --member=allUsers --role=roles/cloudfunctions.invoker