#!/bin/bash
# VUL154 | Authentication | Azure General | Severity: CRITICAL | CVSS: 9.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure App Service with no authentication.

# Step 1: Enable MFA for all users via Conditional Access
az ad conditional-access policy create \
  --name RequireMFA \
  --state enabled

# Step 2: Block legacy authentication protocols
az ad conditional-access policy create \
  --name BlockLegacyAuth \
  --conditions '{"clientAppTypes":["exchangeActiveSync","other"]}' \
  --grant-controls '{"operator":"OR","builtInControls":["block"]}'

# Step 3: Enable Identity Protection
az security setting update \
  --name MCAS \
  --enabled true

# Step 4: Audit sign-in logs for suspicious activity
az monitor activity-log list \
  --filter category eq SignInLogs \
  --output table