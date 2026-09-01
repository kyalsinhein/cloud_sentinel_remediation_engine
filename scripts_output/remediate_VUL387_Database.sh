#!/bin/bash
# VUL387 | Access Control | GCP Database | Severity: HIGH | CVSS: 8.8
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud SQL with misconfigured failover allowing unauthorized access.

# Step 1: Remove the public IP / disable public access
gcloud sql instances patch {{RESOURCE_NAME_VUL387}} --no-assign-ip

# Step 2: Require SSL for all connections (--ssl-mode replaces the
# legacy --require-ssl flag; Google recommends --ssl-mode and warns
# that setting both can conflict)
gcloud sql instances patch {{RESOURCE_NAME_VUL387}} --ssl-mode=ENCRYPTED_ONLY

# Step 3: Rotate the root password
gcloud sql users set-password root --host=% --instance={{RESOURCE_NAME_VUL387}} --password={{NEW_PASSWORD}}

# Step 4: Enable automated backups
gcloud sql instances patch {{RESOURCE_NAME_VUL387}} --backup-start-time=02:00