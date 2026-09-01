#!/bin/bash
# VUL480 | Authentication | Azure API | Severity: CRITICAL | CVSS: 9.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure API Management with misconfigured OAuth2 allowing token theft.

# Step 1: Require a subscription key on the API
az apim api update --resource-group {{RG_NAME}} --service-name {{APIM_NAME}} \
  --api-id {{RESOURCE_NAME_VUL480}} --subscription-required true

# Step 2: Apply an IP-filtering policy
az apim api policy import --resource-group {{RG_NAME}} --service-name {{APIM_NAME}} \
  --api-id {{RESOURCE_NAME_VUL480}} --format xml --value @ip-filter-policy.xml