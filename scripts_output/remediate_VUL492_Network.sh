#!/bin/bash
# VUL492 | Network Security | Azure Network | Severity: MEDIUM | CVSS: 6.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Kubernetes with misconfigured pod network allowing lateral movement.

# Step 1: List all NSG rules allowing Any source
az network nsg rule list \
  --resource-group {{RG_NAME}} \
  --nsg-name {{NSG_NAME}} \
  --query "[?sourceAddressPrefix=='*']" --output table

# Step 2: Delete overly permissive rule
az network nsg rule delete \
  --resource-group {{RG_NAME}} \
  --nsg-name {{NSG_NAME}} \
  --name {{RULE_NAME}}

# Step 3: Add restricted rule from trusted IP
az network nsg rule create \
  --resource-group {{RG_NAME}} \
  --nsg-name {{NSG_NAME}} \
  --name AllowTrustedOnly \
  --priority 100 --direction Inbound --access Allow \
  --protocol Tcp \
  --source-address-prefixes {{TRUSTED_IP}}/32 \
  --destination-port-ranges {{PORT}}

# Step 4: Enable Network Watcher flow logs
az network watcher flow-log create \
  --name FlowLog --nsg {{NSG_NAME}} \
  --resource-group {{RG_NAME}} \
  --storage-account {{STORAGE_ACCOUNT}} --enabled true