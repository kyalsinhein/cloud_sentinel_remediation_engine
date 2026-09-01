#!/bin/bash
# VUL1180 | Access Control | Azure API | Severity: HIGH | CVSS: 8.8
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure API Management with misconfigured subscription policy allowing unauthorized access.

# Step 1: Require a subscription key on the API
az apim api update --resource-group {{RG_NAME}} --service-name {{APIM_NAME}} \
  --api-id {{RESOURCE_NAME_VUL1180}} --subscription-required true

# Step 2: Apply an IP-filtering policy
az apim api policy import --resource-group {{RG_NAME}} --service-name {{APIM_NAME}} \
  --api-id {{RESOURCE_NAME_VUL1180}} --format xml --value @ip-filter-policy.xml