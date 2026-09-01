#!/bin/bash
# VUL527 | Encryption | GCP Database | Severity: MEDIUM | CVSS: 6.0
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud SQL with misconfigured SSL/TLS settings allowing insecure connections.

# Step 1: Remove the public IP / disable public access
gcloud sql instances patch {{RESOURCE_NAME_VUL527}} --no-assign-ip

# Step 2: Require SSL for all connections (--ssl-mode replaces the
# legacy --require-ssl flag; Google recommends --ssl-mode and warns
# that setting both can conflict)
gcloud sql instances patch {{RESOURCE_NAME_VUL527}} --ssl-mode=ENCRYPTED_ONLY

# Step 3: Rotate the root password
gcloud sql users set-password root --host=% --instance={{RESOURCE_NAME_VUL527}} --password={{NEW_PASSWORD}}

# Step 4: Enable automated backups
gcloud sql instances patch {{RESOURCE_NAME_VUL527}} --backup-start-time=02:00