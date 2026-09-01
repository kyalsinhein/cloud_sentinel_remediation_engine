#!/bin/bash
# VUL656 | Access Control | Azure IAM | Severity: HIGH | CVSS: 8.8
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Databricks with misconfigured workspace allowing unauthorized access.

# ── Step 1: List current role assignments ────────────────────────────────
az role assignment list \
  --assignee {{RESOURCE_NAME_VUL656}} \
  --all --output table

# ── Step 2: Remove Owner role at subscription scope ──────────────────────
az role assignment delete \
  --assignee {{RESOURCE_NAME_VUL656}} \
  --role "Owner" \
  --scope /subscriptions/{{SUBSCRIPTION_ID}}

# ── Step 3: Assign least-privilege Contributor at resource group ─────────
az role assignment create \
  --assignee {{RESOURCE_NAME_VUL656}} \
  --role "Contributor" \
  --scope /subscriptions/{{SUBSCRIPTION_ID}}/resourceGroups/{{RESOURCE_GROUP}}

# ── Step 4: Verify updated assignments ───────────────────────────────────
az role assignment list \
  --assignee {{RESOURCE_NAME_VUL656}} \
  --all --output table