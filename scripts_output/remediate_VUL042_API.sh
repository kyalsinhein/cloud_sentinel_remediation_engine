#!/bin/bash
# VUL042 | API Security | Azure API | Severity: MEDIUM | CVSS: 6.9
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Logic Apps with unauthenticated endpoint.

# Step 1: Require a subscription key on the API
az apim api update --resource-group {{RG_NAME}} --service-name {{APIM_NAME}} \
  --api-id {{RESOURCE_NAME_VUL042}} --subscription-required true

# Step 2: Apply an IP-filtering policy
az apim api policy import --resource-group {{RG_NAME}} --service-name {{APIM_NAME}} \
  --api-id {{RESOURCE_NAME_VUL042}} --format xml --value @ip-filter-policy.xml