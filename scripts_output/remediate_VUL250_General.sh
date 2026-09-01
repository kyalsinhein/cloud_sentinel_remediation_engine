#!/bin/bash
# VUL250 | Patch Management | Azure General | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Virtual Machine with no security updates.

# Step 1: Enable automatic patching via Update Manager
az vm update --resource-group {{RG_NAME}} --name {{VM_NAME}} \
  --set osProfile.linuxConfiguration.patchSettings.patchMode=AutomaticByPlatform

# Step 2: Run an on-demand patch assessment
az vm assess-patches --resource-group {{RG_NAME}} --name {{VM_NAME}}

# Step 3: Install available patches
az vm install-patches --resource-group {{RG_NAME}} --name {{VM_NAME}} \
  --maximum-duration PT2H --reboot-setting IfRequired