#!/bin/bash
# VUL293 | Resource Control | GCP General | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Run with no request timeout.

# Step 1: Label the resource for ownership and lifecycle tracking
gcloud resource-manager tags bindings create \
  --tag-value={{TAG_VALUE}} --parent={{RESOURCE_ID}}

# Step 2: Constrain which resource types/locations can be created
gcloud resource-manager org-policies set-policy {{POLICY_FILE}} \
  --project={{PROJECT_ID}}

# Step 3: Review current asset inventory against the new constraint
gcloud asset search-all-resources --scope=projects/{{PROJECT_ID}}