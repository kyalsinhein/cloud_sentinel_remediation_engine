#!/bin/bash
# VUL185 | API Security | GCP API | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Armor with no rate limiting.

# Step 1: Require an API key
gcloud api-gateway api-configs update {{RESOURCE_NAME_VUL185}} --api={{API_ID}} --api-config-id={{CONFIG_ID}}

# Step 2: Attach a Cloud Armor security policy
gcloud compute backend-services update {{BACKEND_SERVICE}} --security-policy={{ARMOR_POLICY}}