#!/bin/bash
# VUL769 | Domain Hijacking | GCP General | Severity: HIGH | CVSS: 8.8
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud DNS with misconfigured record allowing domain hijacking.

# Step 1: List record sets for dangling references
gcloud dns record-sets list --zone={{ZONE_NAME}}

# Step 2: Remove the dangling record
gcloud dns record-sets delete {{RECORD_NAME}} \
  --zone={{ZONE_NAME}} --type=CNAME

# Step 3: Enable DNSSEC on the managed zone
gcloud dns managed-zones update {{ZONE_NAME}} --dnssec-state=on