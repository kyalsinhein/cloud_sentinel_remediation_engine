#!/bin/bash
# VUL468 | Denial of Service | Azure Network | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Virtual Network with misconfigured DDoS protection allowing service disruption.

# Step 1: Enable DDoS Protection Standard on the VNet
az network ddos-protection create \
  --resource-group {{RG_NAME}} --name {{DDOS_PLAN_NAME}}

# Step 2: Add a rate-limit custom rule to the WAF policy
az network application-gateway waf-policy custom-rule create \
  --policy-name {{WAF_POLICY}} --resource-group {{RG_NAME}} \
  --name RateLimitRule --priority 1 --rule-type RateLimitRule \
  --rate-limit-threshold 100 --action Block

# Step 3: Configure autoscale to absorb legitimate traffic spikes
az monitor autoscale create \
  --resource-group {{RG_NAME}} --resource {{VMSS_ID}} \
  --min-count 2 --max-count 10 --count 2