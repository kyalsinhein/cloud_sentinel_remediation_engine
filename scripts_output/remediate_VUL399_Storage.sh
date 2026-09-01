#!/bin/bash
# VUL399 | Data Exfiltration | GCP Storage | Severity: HIGH | CVSS: 7.1
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Storage with misconfigured CORS allowing cross-origin data exfiltration.

# Step 1: Create a VPC Service Controls perimeter
gcloud access-context-manager perimeters create {{PERIMETER_NAME}} \
  --policy={{POLICY_ID}} --resources=projects/{{PROJECT_NUMBER}} \
  --restricted-services=storage.googleapis.com,bigquery.googleapis.com

# Step 2: Enable Cloud DLP inspection job on sensitive datasets
gcloud services enable dlp.googleapis.com

# Step 3: Enable VPC Flow Logs for egress monitoring
gcloud compute networks subnets update {{SUBNET_NAME}} \
  --region={{REGION}} --enable-flow-logs