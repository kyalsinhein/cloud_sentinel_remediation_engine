#!/bin/bash
# VUL031 | Misconfiguration | GCP Storage | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Storage bucket with legacy ACLs.

# Step 1: List current findings for the resource
gcloud scc findings list {{ORG_ID}} \
  --filter='resourceName="{{RESOURCE_NAME}}"'

# Step 2: Review the recommender's suggested remediation
gcloud recommender recommendations list \
  --project={{PROJECT_ID}} --recommender=google.iam.policy.Recommender

# Step 3: Mark the finding as resolved once the fix is applied
gcloud scc findings update {{FINDING_NAME}} --state=INACTIVE