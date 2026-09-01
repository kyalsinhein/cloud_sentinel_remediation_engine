#!/bin/bash
# VUL1109 | Privilege Escalation | GCP Serverless | Severity: CRITICAL | CVSS: 9.4
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Functions with misconfigured IAM role allowing privilege escalation.

# Step 1: Store the exposed secret in Secret Manager
gcloud secrets create {{RESOURCE_NAME_VUL1109}}-secret --data-file={{SECRET_FILE}}

# Step 2: Mount it as a secret instead of a plaintext env var
gcloud functions deploy {{RESOURCE_NAME_VUL1109}} --set-secrets='{{ENV_VAR}}={{RESOURCE_NAME_VUL1109}}-secret:latest'

# Step 3: Restrict who can invoke the function
gcloud functions remove-iam-policy-binding {{RESOURCE_NAME_VUL1109}} \
  --member=allUsers --role=roles/cloudfunctions.invoker