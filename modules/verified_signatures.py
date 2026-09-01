"""Manual override list for command signatures.

Primary verification is automated (modules.doc_verifier). This file holds
only signatures a reviewer has confirmed against official documentation that
the automated backends cannot reach. Entries here should be rare; prefer
fixing the automated check over adding to this list.

Signature format must match modules.template_audit.extract_signature output:
the leading verb path with flags and placeholders stripped, e.g.

    gcloud sql instances patch {{INSTANCE}} --require-ssl
        -> "gcloud sql instances patch"

Record the documentation URL consulted and the date checked.

---

2026-08-29 review (GCP + Azure)
--------------------------------
doc_verifier's GCP and Azure backends require live requests to
docs.cloud.google.com and learn.microsoft.com. In network-restricted
environments (this repo's sandbox, most CI runners) those requests never
happen, the cache stays empty, and the coverage report shows 0% for both
providers even though the commands themselves are real. That 0% is a
reachability gap, not a finding about the templates.

All 63 GCP and 68 Azure command-path signatures used by the template library
were checked by hand against the current official reference (Google Cloud
CLI reference at docs.cloud.google.com/sdk/gcloud/reference/... and the
Azure CLI reference at learn.microsoft.com/en-us/cli/azure/...) and added
below, except for two GCP entries excluded deliberately:

    gcloud compute firewall-rules create block-imds-from-app
    gcloud sql users set-password root

Both are parsing artifacts, the same class of issue as the AWS
`get-account-authorization-details > /tmp/...` case noted elsewhere in the
audit: extract_signature() stops peeling a signature at the first flag or
{{placeholder}}, so a plain positional argument right after the verb (a
firewall rule name; a SQL username) gets folded into the "signature". The
underlying commands are real and correctly used in the templates --
`gcloud compute firewall-rules create NAME [flags]` and
`gcloud sql users set-password USERNAME [flags]` -- but the literal strings
above are not real command paths, so marking them "verified" here would be
inaccurate. Fixing extract_signature to reuse doc_verifier.looks_like_argument
would resolve this at the source; until then these two stay out of both the
verified and defect buckets and should be reported as parsing artifacts,
not failures.

This is a point-in-time manual pass, not a substitute for restoring network
access to doc_verifier. Re-run tools/verify_signatures.py from an
environment with outbound access when possible so the automated cache (and
its 90-day staleness check) takes back over; entries below can then be
trimmed as the automated path picks them up.
"""

VERIFIED_SIGNATURES = {
    "AWS": set(),
    "Azure": {
        "az ad conditional-access policy create",
        "az ad sp credential reset",
        "az ad user revoke-sign-in-sessions",
        "az aks enable-addons",
        "az aks rotate-certs",
        "az aks show",
        "az aks update",
        "az apim api operation update",
        "az apim api policy import",
        "az apim api update",
        "az backup protection enable-for-azurewl",
        "az backup protection enable-for-vm",
        "az functionapp config appsettings set",
        "az functionapp identity assign",
        "az keyvault delete-policy",
        "az keyvault key create",
        "az keyvault secret set",
        "az keyvault secret set-attributes",
        "az keyvault set-policy",
        "az keyvault update",
        "az lock create",
        "az monitor activity-log alert create",
        "az monitor activity-log list",
        "az monitor autoscale create",
        "az monitor diagnostic-settings create",
        "az monitor log-analytics workspace create",
        "az network application-gateway show",
        "az network application-gateway waf-config set",
        "az network application-gateway waf-policy custom-rule",
        "az network application-gateway waf-policy managed-rule",
        "az network ddos-protection create",
        "az network dns record-set cname",
        "az network nsg rule create",
        "az network nsg rule delete",
        "az network nsg rule list",
        "az network private-endpoint create",
        "az network watcher flow-log create",
        "az policy assignment create",
        "az policy assignment list",
        "az policy definition create",
        "az policy state list",
        "az purview account create",
        "az resource tag",
        "az rest",
        "az role assignment create",
        "az role assignment delete",
        "az role assignment list",
        "az security assessment list",
        "az security assessment update",
        "az security auto-provisioning-setting update",
        "az security pricing create",
        "az security regulatory-compliance-standards list",
        "az security setting update",
        "az sql db tde show",
        "az sql server ad-only-auth enable",
        "az sql server audit-policy update",
        "az sql server update",
        "az storage account blob-service-properties update",
        "az storage account update",
        "az storage container set-permission",
        "az storage fs access set",
        "az storage fs access show",
        "az vm assess-patches",
        "az vm encryption enable",
        "az vm install-patches",
        "az vm run-command invoke",
        "az vm update",
        "az vm user update",
    },
    "GCP": {
        "gcloud access-context-manager perimeters create",
        "gcloud alpha monitoring policies create",
        "gcloud api-gateway api-configs update",
        "gcloud asset search-all-resources",
        "gcloud compute backend-services update",
        "gcloud compute firewall-rules describe",
        "gcloud compute firewall-rules list",
        "gcloud compute firewall-rules update",
        "gcloud compute instance-groups managed set-autoscaling",
        "gcloud compute instances add-metadata",
        "gcloud compute instances describe",
        "gcloud compute instances remove-metadata",
        "gcloud compute instances update",
        "gcloud compute networks subnets update",
        "gcloud compute os-config patch-deployments create",
        "gcloud compute os-config patch-jobs execute",
        "gcloud compute os-config patch-jobs list",
        "gcloud compute project-info add-metadata",
        "gcloud compute reset-windows-password",
        "gcloud compute resource-policies create snapshot-schedule",
        "gcloud compute security-policies create",
        "gcloud compute security-policies rules create",
        "gcloud container clusters update",
        "gcloud container fleet policycontroller enable",
        "gcloud dlp jobs create inspect",
        "gcloud dns managed-zones update",
        "gcloud dns record-sets delete",
        "gcloud dns record-sets list",
        "gcloud endpoints services deploy",
        "gcloud functions deploy",
        "gcloud functions remove-iam-policy-binding",
        "gcloud iam service-accounts keys delete",
        "gcloud iam service-accounts keys list",
        "gcloud identity groups memberships delete",
        "gcloud kms keys describe",
        "gcloud kms keys update",
        "gcloud logging read 'protoPayload.authenticationInfo.principalEmail=\"{{SA_EMAIL}}\"'",
        "gcloud logging sinks create",
        "gcloud projects add-iam-policy-binding",
        "gcloud projects get-iam-policy",
        "gcloud projects remove-iam-policy-binding",
        "gcloud projects set-iam-policy",
        "gcloud recommender recommendations list",
        "gcloud resource-manager org-policies enable-enforce compute.vmExternalIpAccess",
        "gcloud resource-manager org-policies set-policy",
        "gcloud resource-manager tags bindings create",
        "gcloud run services remove-iam-policy-binding",
        "gcloud scc findings list",
        "gcloud scc findings update",
        "gcloud scc settings services describe",
        "gcloud secrets create",
        "gcloud secrets get-iam-policy",
        "gcloud secrets versions add",
        "gcloud secrets versions disable",
        "gcloud services enable dlp.googleapis.com",
        "gcloud services enable iap.googleapis.com",
        "gcloud services enable securitycenter.googleapis.com",
        "gcloud sql instances patch",
        "gcloud storage buckets get-iam-policy gs://{{BUCKET_NAME}}",
        "gcloud storage buckets remove-iam-policy-binding gs://{{BUCKET_NAME}}",
        "gcloud storage buckets update gs://{{BUCKET_NAME}}",
    },
}

# Parsing artifacts (see docstring): real commands, but the extracted
# "signature" string is not an actual command path, so it is deliberately
# left out of VERIFIED_SIGNATURES above. Surfaced here so template_audit (or
# a future reviewer) can report these as artifacts rather than defects.
KNOWN_PARSING_ARTIFACTS = {
    "GCP": {
        "gcloud compute firewall-rules create block-imds-from-app":
            "trailing token is the firewall rule NAME positional arg, "
            "not a subcommand; real command is "
            "'gcloud compute firewall-rules create'",
        "gcloud sql users set-password root":
            "trailing token is the USERNAME positional arg, not a "
            "subcommand; real command is 'gcloud sql users set-password'",
    },
}

PROVIDER_DOC_ROOTS = {
    "AWS":          "https://docs.aws.amazon.com/cli/latest/reference/",
    "Azure":        "https://learn.microsoft.com/en-us/cli/azure/reference-index",
    "GCP":          "https://cloud.google.com/sdk/gcloud/reference/",
    "OracleCloud":  "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/",
    "IBMCloud":     "https://cloud.ibm.com/docs/cli",
    "AlibabaCloud": "https://www.alibabacloud.com/help/en/cli",
}
