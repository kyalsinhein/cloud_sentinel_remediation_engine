#!/bin/bash
# VUL006 | Network Security | GCP Compute | Severity: MEDIUM | CVSS: 6.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Compute Engine instance with overly permissive firewall rules.

# Step 1: Enforce OS Login at the project level (removes reliance on embedded SSH keys)
gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE

# Step 2: Remove the exposed/default SSH key from instance metadata
gcloud compute instances remove-metadata {{RESOURCE_NAME_VUL006}} --zone {{ZONE}} --keys=ssh-keys

# Step 3: Enable Shielded VM options
gcloud compute instances update {{RESOURCE_NAME_VUL006}} --zone {{ZONE}} \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring

# Step 4: Restrict the firewall rule to a trusted CIDR only
gcloud compute firewall-rules update {{FIREWALL_RULE}} --source-ranges={{TRUSTED_CIDR}}