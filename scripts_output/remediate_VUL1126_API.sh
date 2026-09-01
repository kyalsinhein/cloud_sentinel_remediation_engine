#!/bin/bash
# VUL1126 | Data Exposure | Azure API | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure API Management with misconfigured backend exposing internal services.

# Step 1: Require a subscription key on the API
az apim api update --resource-group {{RG_NAME}} --service-name {{APIM_NAME}} \
  --api-id {{RESOURCE_NAME_VUL1126}} --subscription-required true

# Step 2: Apply an IP-filtering policy
az apim api policy import --resource-group {{RG_NAME}} --service-name {{APIM_NAME}} \
  --api-id {{RESOURCE_NAME_VUL1126}} --format xml --value @ip-filter-policy.xml