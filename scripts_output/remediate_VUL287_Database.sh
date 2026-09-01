#!/bin/bash
# VUL287 | Data Protection | GCP Database | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud SQL with no point-in-time recovery.

# Step 1: Remove the public IP / disable public access
gcloud sql instances patch {{RESOURCE_NAME_VUL287}} --no-assign-ip

# Step 2: Require SSL for all connections (--ssl-mode replaces the
# legacy --require-ssl flag; Google recommends --ssl-mode and warns
# that setting both can conflict)
gcloud sql instances patch {{RESOURCE_NAME_VUL287}} --ssl-mode=ENCRYPTED_ONLY

# Step 3: Rotate the root password
gcloud sql users set-password root --host=% --instance={{RESOURCE_NAME_VUL287}} --password={{NEW_PASSWORD}}

# Step 4: Enable automated backups
gcloud sql instances patch {{RESOURCE_NAME_VUL287}} --backup-start-time=02:00