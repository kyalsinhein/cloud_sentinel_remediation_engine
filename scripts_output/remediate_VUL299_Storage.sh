#!/bin/bash
# VUL299 | Data Protection | GCP Storage | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Storage with no object versioning.

# Step 1: Enable object versioning on the bucket
gsutil versioning set on gs://{{RESOURCE_NAME_VUL299}}

# Step 2: Configure a scheduled backup / snapshot policy
gcloud compute resource-policies create snapshot-schedule {{SCHEDULE_NAME}} \
  --project={{PROJECT_ID}} --region={{REGION}} \
  --max-retention-days=30 --daily-schedule --start-time=03:00

# Step 3: Run a Cloud DLP inspection job to find sensitive data
gcloud dlp jobs create inspect \
  --project={{PROJECT_ID}} \
  --storage-config='{"cloudStorageOptions":{"fileSet":{"url":"gs://{{RESOURCE_NAME_VUL299}}/*"}}}'