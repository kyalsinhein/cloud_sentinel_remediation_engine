#!/bin/bash
# VUL674 | Privilege Escalation | Azure IAM | Severity: CRITICAL | CVSS: 9.4
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Virtual Machine with misconfigured extension allowing privilege escalation.

# Step 1: Audit all Owner/Contributor assignments
az role assignment list \
  --role Owner --all --output table

# Step 2: Remove direct Owner assignments
az role assignment delete \
  --assignee {{PRINCIPAL_ID}} \
  --role Owner \
  --scope {{SCOPE}}

# Step 3: List current permanent-vs-PIM-eligible role assignment schedules.
# This is a read-only audit step - it does not itself enforce anything.
az rest --method GET \
  --url https://management.azure.com/providers/Microsoft.Authorization/roleAssignmentSchedules?api-version=2020-10-01

# Step 4: Convert a remaining permanent Owner assignment to a time-bound
# PIM-eligible assignment. The request body's schedule/justification
# fields must be authored by the reviewer - there is no safe default here.
az rest --method PUT \
  --url https://management.azure.com/{{SCOPE}}/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/{{REQUEST_GUID}}?api-version=2020-10-01 \
  --body '{{PIM_ELIGIBILITY_REQUEST_BODY}}'

# Step 5: Enable Microsoft Defender for Resource Manager - flags anomalous
# role-assignment / ARM control-plane activity (Defender for Identity is a
# separate product not managed via `az security pricing`).
az security pricing create \
  --name Arm --tier Standard