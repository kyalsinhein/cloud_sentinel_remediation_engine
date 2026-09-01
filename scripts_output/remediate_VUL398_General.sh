#!/bin/bash
# VUL398 | Domain Hijacking | Azure General | Severity: HIGH | CVSS: 8.8
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure App Service with misconfigured custom domain allowing subdomain takeover.

# Step 1: List CNAME records pointing to deprovisioned Azure resources
az network dns record-set cname list \
  --resource-group {{RG_NAME}} --zone-name {{ZONE_NAME}}

# Step 2: Remove the dangling record
az network dns record-set cname remove-record \
  --resource-group {{RG_NAME}} --zone-name {{ZONE_NAME}} \
  --record-set-name {{RECORD_NAME}} --cname {{TARGET}}

# Step 3: Apply a resource lock on the DNS zone
az lock create --name DoNotDeleteDNS --resource-group {{RG_NAME}} \
  --resource-name {{ZONE_NAME}} --resource-type Microsoft.Network/dnszones \
  --lock-type CanNotDelete