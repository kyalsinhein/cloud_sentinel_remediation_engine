#!/bin/bash
# VUL1020 | Authentication | Azure Network | Severity: CRITICAL | CVSS: 9.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Virtual Machine with misconfigured network security group allowing RDP brute force.

# ── Step 1: Remove any existing allow-all RDP rules ──────────────────────
az network nsg rule delete \
  --resource-group {{RESOURCE_GROUP}} \
  --nsg-name {{RESOURCE_NAME_VUL1020}} \
  --name Allow-RDP-All

# ── Step 2: Allow RDP from trusted IP only ───────────────────────────────
az network nsg rule create \
  --resource-group {{RESOURCE_GROUP}} \
  --nsg-name {{RESOURCE_NAME_VUL1020}} \
  --name Allow-RDP-Trusted \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --source-address-prefixes {{TRUSTED_IP}}/32 \
  --destination-port-ranges 3389

# ── Step 3: Deny all other RDP ───────────────────────────────────────────
az network nsg rule create \
  --resource-group {{RESOURCE_GROUP}} \
  --nsg-name {{RESOURCE_NAME_VUL1020}} \
  --name Deny-RDP-All \
  --priority 200 \
  --direction Inbound \
  --access Deny \
  --protocol Tcp \
  --source-address-prefixes '*' \
  --destination-port-ranges 3389

# ── Step 4: Verify final NSG rules ───────────────────────────────────────
az network nsg rule list \
  --resource-group {{RESOURCE_GROUP}} \
  --nsg-name {{RESOURCE_NAME_VUL1020}} \
  --output table