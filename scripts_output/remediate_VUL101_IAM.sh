#!/bin/bash
# VUL101 | Security Policy | GCP IAM | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Compute Engine with no shielded VMs.

# Step 1: Set an organization policy constraint (e.g. restrict public IP)
gcloud resource-manager org-policies enable-enforce \
  compute.vmExternalIpAccess --organization={{ORG_ID}}

# Step 2: Confirm Security Command Center is enabled to monitor compliance
gcloud scc settings services describe SECURITY_HEALTH_ANALYTICS \
  --organization={{ORG_ID}}

# Step 3: List current findings against the new constraint
gcloud scc findings list {{ORG_ID}} --filter='category="PUBLIC_IP_ADDRESS"'