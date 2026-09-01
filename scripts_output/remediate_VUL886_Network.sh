#!/bin/bash
# VUL886 | Data Exfiltration | Azure Network | Severity: HIGH | CVSS: 7.1
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Virtual Network with misconfigured service endpoint allowing data exfiltration.

# Step 1: Enable Microsoft Defender for Cloud (all plans)
az security pricing create --name StorageAccounts --tier Standard

# Step 2: Restrict outbound traffic on NSG to approved endpoints only
az network nsg rule create \
  --resource-group {{RG_NAME}} --nsg-name {{NSG_NAME}} \
  --name DenyAllOutbound --priority 4096 \
  --direction Outbound --access Deny --protocol '*' \
  --destination-address-prefixes '*'

# Step 3: Enable Private Link for storage/database access
az network private-endpoint create \
  --name {{PE_NAME}} --resource-group {{RG_NAME}} \
  --vnet-name {{VNET_NAME}} --subnet {{SUBNET_NAME}} \
  --private-connection-resource-id {{RESOURCE_ID}} \
  --group-id blob --connection-name {{CONNECTION_NAME}}