#!/bin/bash
# VUL143 | Authentication | GCP Container | Severity: CRITICAL | CVSS: 9.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Kubernetes Engine with legacy authorization enabled.

# Step 1: Disable legacy basic auth and client certificates
gcloud container clusters update {{RESOURCE_NAME_VUL143}} --zone {{ZONE}} \
  --no-issue-client-certificate

# Step 2: Enable Workload Identity (replace broad node service-account perms)
gcloud container clusters update {{RESOURCE_NAME_VUL143}} --zone {{ZONE}} \
  --workload-pool={{PROJECT_ID}}.svc.id.goog

# Step 3: Restrict the control plane to authorized networks only
gcloud container clusters update {{RESOURCE_NAME_VUL143}} --zone {{ZONE}} \
  --enable-master-authorized-networks --master-authorized-networks={{TRUSTED_CIDR}}

# Step 4: Enable private cluster (no public control-plane endpoint)
gcloud container clusters update {{RESOURCE_NAME_VUL143}} --zone {{ZONE}} --enable-private-endpoint