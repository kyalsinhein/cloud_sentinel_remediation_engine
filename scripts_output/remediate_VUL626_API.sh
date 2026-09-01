#!/bin/bash
# VUL626 | Data Exfiltration | Azure API | Severity: HIGH | CVSS: 7.1
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure API Management with misconfigured CORS allowing cross-origin attacks.

# Step 1: Require a subscription key on the API
az apim api update --resource-group {{RG_NAME}} --service-name {{APIM_NAME}} \
  --api-id {{RESOURCE_NAME_VUL626}} --subscription-required true

# Step 2: Apply an IP-filtering policy
az apim api policy import --resource-group {{RG_NAME}} --service-name {{APIM_NAME}} \
  --api-id {{RESOURCE_NAME_VUL626}} --format xml --value @ip-filter-policy.xml