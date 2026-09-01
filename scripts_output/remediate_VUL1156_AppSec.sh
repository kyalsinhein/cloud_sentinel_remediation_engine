#!/bin/bash
# VUL1156 | Code Injection | Azure AppSec | Severity: CRITICAL | CVSS: 9.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Databricks with misconfigured notebook allowing code injection.

# Step 1: Enable WAF on Application Gateway
az network application-gateway waf-config set \
  --gateway-name {{APPGW_NAME}} --resource-group {{RG_NAME}} \
  --enabled true --firewall-mode Prevention

# Step 2: Enable OWASP managed rule set (SQLi / XSS)
az network application-gateway waf-policy managed-rule rule-set add \
  --policy-name {{WAF_POLICY}} --resource-group {{RG_NAME}} \
  --type OWASP --version 3.2

# Step 3: Restrict Function App execution identity
az functionapp identity assign --name {{FUNCTION_APP}} --resource-group {{RG_NAME}}