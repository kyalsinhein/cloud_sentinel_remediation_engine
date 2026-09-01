#!/bin/bash
# VUL721 | Denial of Service | GCP Serverless | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Functions with misconfigured memory limit allowing resource exhaustion.

# Step 1: Store the exposed secret in Secret Manager
gcloud secrets create {{RESOURCE_NAME_VUL721}}-secret --data-file={{SECRET_FILE}}

# Step 2: Mount it as a secret instead of a plaintext env var
gcloud functions deploy {{RESOURCE_NAME_VUL721}} --set-secrets='{{ENV_VAR}}={{RESOURCE_NAME_VUL721}}-secret:latest'

# Step 3: Restrict who can invoke the function
gcloud functions remove-iam-policy-binding {{RESOURCE_NAME_VUL721}} \
  --member=allUsers --role=roles/cloudfunctions.invoker