#!/bin/bash
# VUL064 | API Security | Azure API | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure API Management with no authentication.

# Step 1: Require a subscription key on the API
az apim api update --resource-group {{RG_NAME}} --service-name {{APIM_NAME}} \
  --api-id {{RESOURCE_NAME_VUL064}} --subscription-required true

# Step 2: Apply an IP-filtering policy
az apim api policy import --resource-group {{RG_NAME}} --service-name {{APIM_NAME}} \
  --api-id {{RESOURCE_NAME_VUL064}} --format xml --value @ip-filter-policy.xml