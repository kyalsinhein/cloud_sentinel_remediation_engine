#!/bin/bash
# VUL374 | Injection | Azure AppSec | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Stream Analytics with misconfigured input allowing data injection.

# Step 1: Enable WAF on the Application Gateway
az network application-gateway waf-config set \
  --gateway-name {{GATEWAY_NAME}} --resource-group {{RG_NAME}} \
  --enabled true --firewall-mode Prevention

# Step 2: Attach the OWASP Core Rule Set for SQLi/XSS coverage
az network application-gateway waf-policy managed-rule rule-set add \
  --policy-name {{WAF_POLICY_NAME}} --resource-group {{RG_NAME}} \
  --type OWASP --version 3.2

# Step 3: Confirm the policy is linked to the listener
az network application-gateway show --name {{GATEWAY_NAME}} \
  --resource-group {{RG_NAME}} --query 'firewallPolicy'