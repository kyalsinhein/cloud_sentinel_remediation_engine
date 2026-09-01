# -*- coding: utf-8 -*-
"""Remediation mapping engine.

Maps dataset records to validated CLI remediation templates using a
deterministic key built from category, cloud provider and service. Records
with no matching template receive a scaffold for manual completion.
"""

import json
import re
import sys
import pandas as pd
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

TEMPLATES_PATH = Path(__file__).resolve().parent.parent / "templates" / "remediation_templates.json"


def _normalize_key(key: str) -> str:
    """
    Canonical form used for all key comparisons, so case, spacing and
    separator differences between the JSON and built-in template sets cannot
    cause a false miss.
    """
    return re.sub(r"\s+", "_", str(key).strip().upper())


# Maps the generic service tag from data_loader._infer_service() to the
# resource-specific names some templates use, so generic-service records can
# still reach the more specific templates.
_SERVICE_ALIASES = {
    "AWS": {
        "Storage": "S3", "Compute": "EC2", "Database": "RDS",
        "Logging": "CloudTrail", "Encryption": "KMS",
    },
    "AZURE": {
        "IAM": "RBAC", "Encryption": "KeyVault",
    },
}


def _load_templates() -> dict:
    """
    Merge both template sources: the resource-specific library in
    templates/remediation_templates.json and the category-level built-ins
    below. JSON entries take precedence on an exact key collision.
    """
    merged = dict(_BUILTIN_TEMPLATES)
    try:
        with open(TEMPLATES_PATH, "r", encoding="utf-8") as fh:
            file_templates = json.load(fh)
        merged.update(file_templates)
    except FileNotFoundError:
        # Warn rather than fail silently: a wrong path would otherwise drop
        # every resource-specific template and send all records to the
        # generic fallback with no indication why.
        import warnings
        warnings.warn(
            "Could not find {} - only the {} generic built-in category "
            "templates are active; ALL resource-specific templates "
            "(S3, RDS, AKS, etc.) are unavailable. Verify TEMPLATES_PATH "
            "matches your actual project layout.".format(
                TEMPLATES_PATH, len(_BUILTIN_TEMPLATES)),
            RuntimeWarning,
        )
    except json.JSONDecodeError as e:
        import warnings
        warnings.warn(
            "{} exists but is not valid JSON ({}) - only the {} generic "
            "built-in category templates are active.".format(
                TEMPLATES_PATH, e, len(_BUILTIN_TEMPLATES)),
            RuntimeWarning,
        )
    return merged


def templates_health_check() -> dict:
    """
    Report whether the JSON template library loaded, for display after the
    templates are read.
    """
    json_loaded = TEMPLATES_PATH.exists()
    merged = _load_templates()
    return {
        "templates_json_path":      str(TEMPLATES_PATH),
        "templates_json_found":     json_loaded,
        "builtin_template_count":   len(_BUILTIN_TEMPLATES),
        "total_template_count":     len(merged),
        "resource_specific_count":  len(merged) - len(_BUILTIN_TEMPLATES),
    }


def _normalized_index(templates: dict) -> dict:
    """Build a case/format-insensitive lookup index over a templates dict."""
    return {_normalize_key(k): v for k, v in templates.items()}


# Step 3.1: Detect cloud provider
def detect_provider(row: pd.Series) -> str:
    provider = str(row.get("cloud_provider", "")).strip().upper()
    if "AWS" in provider or "AMAZON" in provider:
        return "AWS"
    if "AZURE" in provider or "MICROSOFT" in provider:
        return "Azure"
    if "GCP" in provider or ("GOOGLE" in provider and "ALIBABA" not in provider):
        return "GCP"
    if "ORACLE" in provider or "OCI" in provider:
        return "OracleCloud"
    if "IBM" in provider:
        return "IBMCloud"
    if "ALIBABA" in provider or "ALIYUN" in provider:
        return "AlibabaCloud"

    # Fallback: scan description
    text = str(row.get("description", "")).lower()
    if any(k in text for k in ["aws", "s3", "ec2", "iam", "lambda", "cloudtrail"]):
        return "AWS"
    if any(k in text for k in ["azure", "blob", "keyvault", "nsg"]):
        return "Azure"
    if any(k in text for k in ["gcp", "gke", "bigquery", "cloud run"]):
        return "GCP"
    if any(k in text for k in ["oracle cloud", "oci ", "autonomous database"]):
        return "OracleCloud"
    if any(k in text for k in ["ibm cloud", "ibm cos", "watson"]):
        return "IBMCloud"
    if any(k in text for k in ["alibaba", "aliyun", "ram policy", "oss bucket"]):
        return "AlibabaCloud"

    # Last resort: use the dataset's own cloud_provider value verbatim
    # instead of guessing AWS, so an unrecognised provider falls through
    # to the scaffold rather than being mapped to the wrong provider.
    return provider.title().replace(" ", "") if provider and provider != "UNKNOWN" else "Unknown"


# Keyword-based overrides.
#
# The 12 dataset categories are coarse - e.g. "Authentication" covers both
# exposed API keys (IAM fix) and default OS logins (OS fix). When the
# description matches a known pattern, route to a more specific template,
# checked before the generic CATEGORY|PROVIDER template.
_KEYWORD_OVERRIDES = [
    # (match-keywords, override key prefix)
    (("default credential", "default password", "default admin", "default login"),
     "DEFAULT_CREDENTIALS"),
    (("root account access key", "root access key", "root user access key",
      "root credentials"),
     "ROOT_ACCOUNT_KEYS"),
]


def _keyword_override_keys(category: str, provider: str, description: str,
                             service: str = "") -> list:
    text = str(description).lower()
    p = str(provider).strip().upper()
    s = str(service).strip().upper()
    keys = []
    for keywords, prefix in _KEYWORD_OVERRIDES:
        if any(k in text for k in keywords):
            if s:
                keys.append("{}|{}|{}".format(prefix, p, s))   # service-specific first
            keys.append("{}|{}".format(prefix, p))              # generic fallback
    return keys


# vulnerable_code-based override: data-plane vs. control-plane.
#
# `vulnerable_code` holds the actual misconfigured artifact (IAM/bucket
# policy JSON, a CLI call, etc.), not just a category label. Category alone
# can't tell an over-permissioned IAM role (control-plane/RBAC fix) apart
# from a public bucket ACL (data-plane fix), even though both often land
# under "Privilege Escalation" or "Access Control" and need different
# commands. Checked before the category-based keys for the same reason.
_DATA_PLANE_WILDCARD_MARKERS = (
    '"principal": "*"', '"principal":"*"',
    '"principalid": "*"', '"principalid":"*"',
    '"principal": "anyuser"', '"principal":"anyuser"',
    'allusers', 'allauthenticatedusers',
    'publicaccess',
)


def _has_data_plane_wildcard(vulnerable_code: str) -> bool:
    """
    True if vulnerable_code looks like a data-plane resource (bucket policy,
    storage ACL, IAM binding on a resource) granting access to a wildcard
    principal, rather than a control-plane role/permission definition.
    """
    text = str(vulnerable_code or "").strip()
    if not text:
        return False

    # Prefer a structured parse so key/value pairs are matched precisely
    # rather than by raw substring (e.g. avoids false positives on a
    # description that merely mentions "AllUsers" in prose).
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        obj = None

    flat = json.dumps(obj).lower() if isinstance(obj, (dict, list)) else text.lower()
    return any(marker in flat for marker in _DATA_PLANE_WILDCARD_MARKERS)


def _vulnerable_code_override_keys(vulnerable_code: str, provider: str,
                                    severity: str = "") -> list:
    p = str(provider).strip().upper()
    sev = str(severity).strip().upper()
    if not _has_data_plane_wildcard(vulnerable_code):
        return []
    keys = []
    if sev:
        keys.append("DATA_PLANE_PUBLIC_ACCESS|{}|{}".format(p, sev))
    keys.append("DATA_PLANE_PUBLIC_ACCESS|{}".format(p))
    return keys


# Privileged-workload override: cluster-auth vs. pod/workload security.
#
# A Kubernetes/ECS/GKE "Container" finding can mean the cluster's
# control-plane credentials are too permissive (an IRSA/Workload Identity
# fix - what CONTAINER|<provider> covers), or that a pod can run privileged
# / escape to the host (a PodSecurityPolicy/admission-policy fix instead).
# The bare CONTAINER|<provider> key used to match both, so privileged-pod
# findings silently got the wrong template. This override is checked ahead
# of that bare key, same precedence as the data-plane-wildcard override.
# Unambiguous: these key names only occur in a Kubernetes/pod spec, so they
# are trusted on their own regardless of surrounding description text.
_PRIVILEGED_WORKLOAD_CODE_MARKERS_STRONG = (
    'podsecuritypolicy',
    '"hostpid": true', '"hostpid":true',
    '"hostipc": true', '"hostipc":true',
    '"hostnetwork": true', '"hostnetwork":true',
    'initcontainers',
)

# Ambiguous: bare "privileged": true / "allowPrivilegeEscalation": true also
# appear on non-container resources (e.g. VUL674, a VM extension config).
# These only count when corroborated by container/Kubernetes context
# elsewhere in the record (see _has_privileged_workload_config below).
_PRIVILEGED_WORKLOAD_CODE_MARKERS_WEAK = (
    '"privileged": true', '"privileged":true',
    '"allowprivilegeescalation": true', '"allowprivilegeescalation":true',
)

_CONTAINER_CONTEXT_KEYWORDS = (
    "kubernetes", "k8s", "pod", "container", "aks", "eks", "gke", "ecs", "docker",
)


# Narrow on purpose: most Kubernetes privilege-escalation findings here are
# actually about the control plane (RBAC, cluster roles, service accounts)
# and should keep routing to PRIVILEGE_ESCALATION|<provider> /
# CONTAINER|<provider>. Only pod-spec/task-definition settings belong here.
_PRIVILEGED_WORKLOAD_DESCRIPTION_KEYWORDS = (
    "pod security policy", "podsecuritypolicy", "pod security context",
    "privileged container", "privileged pod", "container breakout",
    "allowprivilegeescalation",
)


def _has_privileged_workload_config(vulnerable_code: str, description: str = "",
                                     service: str = "") -> bool:
    """
    True if vulnerable_code looks like a workload/pod-spec security setting
    (PodSecurityPolicy, securityContext, etc.) rather than a control-plane
    cluster-auth/IAM setting or an unrelated resource that happens to share
    the word "privileged" (e.g. a VM extension - see VUL674).
    """
    text = str(vulnerable_code or "").strip()
    if not text:
        return False
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        obj = None
    flat = json.dumps(obj).lower() if isinstance(obj, (dict, list)) else text.lower()

    if any(marker in flat for marker in _PRIVILEGED_WORKLOAD_CODE_MARKERS_STRONG):
        return True
    if any(marker in flat for marker in _PRIVILEGED_WORKLOAD_CODE_MARKERS_WEAK):
        ctx = (str(description) + " " + str(service)).lower()
        return any(kw in ctx for kw in _CONTAINER_CONTEXT_KEYWORDS)
    return False


def _has_privileged_workload_description(description: str) -> bool:
    text = str(description or "").lower()
    return any(kw in text for kw in _PRIVILEGED_WORKLOAD_DESCRIPTION_KEYWORDS)


def _is_ecs_task_definition(vulnerable_code: str, description: str) -> bool:
    """
    AWS-specific split: ECS task-definition privilege issues are fixed via
    `aws ecs register-task-definition` (no cluster, no kubectl - ECS isn't
    Kubernetes), so they need their own template rather than the
    EKS/kubectl-based PRIVILEGED_WORKLOAD|AWS one.
    """
    text = (str(vulnerable_code) + " " + str(description)).lower()
    return ("taskdefinition" in text or "containerdefinitions" in text
            or " ecs " in (" " + text + " "))


def _privileged_workload_override_keys(vulnerable_code: str, description: str,
                                        provider: str, severity: str = "",
                                        service: str = "") -> list:
    p = str(provider).strip().upper()
    sev = str(severity).strip().upper()
    if not (_has_privileged_workload_config(vulnerable_code, description, service)
            or _has_privileged_workload_description(description)):
        return []
    prefix = "PRIVILEGED_WORKLOAD"
    if p == "AWS" and _is_ecs_task_definition(vulnerable_code, description):
        prefix = "PRIVILEGED_ECS_TASK"
    keys = []
    if sev:
        keys.append("{}|{}|{}".format(prefix, p, sev))
    keys.append("{}|{}".format(prefix, p))
    return keys


# Step 3.2: Build lookup key candidates, most specific -> least specific.
# Tries both the "SERVICE|PROVIDER|SEVERITY" schema (JSON library) and the
# "CATEGORY|PROVIDER" schema (built-in library), including AWS/Azure
# resource-name aliases, so a match is found in either library.
#
# Severity-qualified keys are tried before bare/unqualified ones. Several
# services have both a bare generic template (e.g. "COMPUTE|AWS") and a
# resource-specific, severity-qualified template for the same finding (e.g.
# "EC2|AWS|HIGH"). Index lookup stops at the first match, so checking the
# bare key first would always shadow the more accurate one.
def _build_key(category: str, provider: str, service: str, severity: str = "",
                description: str = "", vulnerable_code: str = "") -> list:
    c = str(category).strip().upper().replace(" ", "_")
    p = str(provider).strip().upper()
    s = str(service).strip().upper()
    sev = str(severity).strip().upper()
    alias = _SERVICE_ALIASES.get(p, {}).get(str(service).strip(), None)
    a = str(alias).strip().upper() if alias else None

    keys = []
    # vulnerable_code-derived overrides go first: they read the actual
    # misconfigured artifact rather than free text, so they're the most
    # direct signal for data-plane-vs-control-plane and
    # workload-vs-cluster-auth routing.
    keys.extend(_vulnerable_code_override_keys(vulnerable_code, provider, severity))
    keys.extend(_privileged_workload_override_keys(vulnerable_code, description,
                                                     provider, severity, service))

    # Keyword overrides next - most specific, checked before anything else.
    keys.extend(_keyword_override_keys(category, provider, description, service))

    # Severity-qualified keys, most resource-specific first.
    if sev:
        if a:
            keys.append("{}|{}|{}".format(a, p, sev))
        keys.append("{}|{}|{}".format(s, p, sev))
        keys.append("{}|{}|{}".format(c, p, sev))

    # Bare resource-specific keys (SERVICE|PROVIDER) before the generic
    # CATEGORY|PROVIDER key, which exists for all 72 category/provider
    # combos and would otherwise always win.
    if a:
        keys.append("{}|{}".format(a, p))
    keys.append("{}|{}".format(s, p))
    keys.append("{}|{}".format(c, p))     # category + provider (generic fallback)
    keys.append(c)
    keys.append(s)

    seen, ordered = set(), []
    for k in keys:
        if k not in seen:
            seen.add(k)
            ordered.append(k)
    return ordered


# Step 3.3: Populate template with resource metadata
def _populate(commands: list, row: pd.Series) -> list:
    # The dataset carries a vulnerability ID (e.g. "VUL005"), not a real
    # resource name/ARN. Use resource_name/resource_id when the dataset
    # supplies one; otherwise fall back to a bracketed {{PLACEHOLDER}} so
    # it's caught by the HITL "replace placeholder values" step and by
    # syntax_audit_script(), instead of silently substituting the ID.
    vuln_id  = str(row.get("id", "VULN_ID"))
    resource = str(row.get("resource_name", "") or row.get("resource_id", "")) \
               or "{{RESOURCE_NAME_" + vuln_id + "}}"
    provider   = detect_provider(row)
    category   = str(row.get("category", ""))
    service    = str(row.get("service", ""))
    description = str(row.get("description", ""))

    populated = []
    for line in commands:
        line = line.replace("{{resource}}", resource)
        line = line.replace("{{VULN_ID}}", vuln_id)
        line = line.replace("{{CATEGORY}}", category)
        line = line.replace("{{SERVICE}}", service)
        populated.append(line)
    return populated


# Precondition-conflict detection.
#
# Templates are chosen from category/provider/service only, without looking
# at `vulnerable_code`. Occasionally the sample already has a flag set that
# the matched template also applies (e.g. --no-assign-ip already present,
# and step 1 sets it again). That step is then a no-op, and the real fix
# may be something else. This surfaces the conflict for the HITL reviewer
# rather than trying to auto-correct it.
_FLAG_PATTERN = re.compile(r"--[a-zA-Z][a-zA-Z0-9-]*")


def _extract_flags(text: str) -> set:
    return set(_FLAG_PATTERN.findall(str(text)))


def detect_precondition_conflict(vulnerable_code: str, script_lines: list) -> dict:
    """
    Compares CLI flags already present in vulnerable_code against flags the
    generated remediation script applies. An overlap means the remediation
    step is likely already satisfied by the vulnerable resource as
    described, i.e. the generated fix may not address the real gap.
    """
    vuln_flags = _extract_flags(vulnerable_code)
    if not vuln_flags:
        return {"conflict": False, "note": ""}

    remediation_flags = _extract_flags("\n".join(script_lines))
    overlap = vuln_flags & remediation_flags
    if not overlap:
        return {"conflict": False, "note": ""}

    return {
        "conflict": True,
        "note": (
            "vulnerable_code already applies {} - the matched template's step(s) "
            "using the same flag(s) may be a no-op against the resource as "
            "described. The generated script may not address the actual gap; "
            "verify against the real resource before approving."
        ).format(", ".join(sorted(overlap))),
    }


# Main: generate a script for one vulnerability record
def generate_script(vuln: pd.Series, templates: dict = None) -> dict:
    if templates is None:
        templates = _load_templates()

    provider = detect_provider(vuln)
    category = str(vuln.get("category", "General"))
    service  = str(vuln.get("service",  "General"))
    severity = str(vuln.get("severity", "MEDIUM"))
    description = str(vuln.get("description", ""))
    vulnerable_code = str(vuln.get("vulnerable_code", ""))

    keys = _build_key(category, provider, service, severity, description, vulnerable_code)
    index = _normalized_index(templates)

    template = None
    matched_key = None
    for k in keys:
        nk = _normalize_key(k)
        if nk in index:
            template = index[nk]
            matched_key = k
            break

    if template:
        lines = _populate(template["commands"], vuln)
        conflict = detect_precondition_conflict(vulnerable_code, lines)
        return {
            "matched_key":  matched_key,
            "title":        template["title"],
            "description":  template.get("description", ""),
            "script_lines": lines,
            "script_text":  _wrap_script(vuln, lines, provider),
            "matched":      True,
            "precondition_conflict":      conflict["conflict"],
            "precondition_conflict_note": conflict["note"],
        }
    else:
        fallback = _scaffold(category, provider, service, str(vuln.get("id", "")))
        conflict = detect_precondition_conflict(vulnerable_code, fallback)
        return {
            "matched_key":  "FALLBACK",
            "title":        "Manual Review Required - {} ({})".format(category, provider),
            "description":  "No template found. Scaffold generated for manual completion.",
            "script_lines": fallback,
            "script_text":  _wrap_script(vuln, fallback, provider),
            "matched":      False,
            "precondition_conflict":      conflict["conflict"],
            "precondition_conflict_note": conflict["note"],
        }


def _wrap_script(vuln: pd.Series, lines: list, provider: str) -> str:
    cvss = vuln.get("cvss_adjusted", vuln.get("cvss_base", "N/A"))
    header = [
        "#!/bin/bash",
        "# ================================================================",
        "# Cloud Sentinel Remediation Engine - Generated Script",
        "# Vulnerability  : {}".format(vuln.get("id", "N/A")),
        "# Category       : {}".format(vuln.get("category", "N/A")),
        "# Cloud Provider : {}".format(provider),
        "# Service        : {}".format(vuln.get("service", "N/A")),
        "# Severity       : {}".format(vuln.get("severity", "N/A")),
        "# CVSS v4.0      : {}".format(cvss),
        "# Generated      : {}".format(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
        "# ----------------------------------------------------------------",
        "# [!] HUMAN-IN-THE-LOOP CHECKPOINT",
        "#     For REVIEW ONLY. Replace {{PLACEHOLDER}} values.",
        "#     Verify in non-production before executing.",
        "#     Computer Misuse Act 1990 compliant - no live changes.",
        "# ================================================================",
        "",
        "# Vulnerability Description:",
        "# {}".format(str(vuln.get("description", ""))[:120]),
        "",
    ]
    return "\n".join(header + lines)


_PROVIDER_CLI = {
    "AWS":          "aws",
    "Azure":        "az",
    "GCP":          "gcloud",
    "OracleCloud":  "oci",
    "IBMCloud":     "ibmcloud",
    "AlibabaCloud": "aliyun",
}

_PROVIDER_DOCS = {
    "AWS":          "https://docs.aws.amazon.com/",
    "Azure":        "https://learn.microsoft.com/en-us/azure/",
    "GCP":          "https://cloud.google.com/docs",
    "OracleCloud":  "https://docs.oracle.com/en-us/iaas/Content/home.htm",
    "IBMCloud":     "https://cloud.ibm.com/docs",
    "AlibabaCloud": "https://www.alibabacloud.com/help",
}


def _scaffold(category: str, provider: str, service: str, vuln_id: str) -> list:
    cli = _PROVIDER_CLI.get(provider, "cli")
    doc = _PROVIDER_DOCS.get(provider, "https://www.google.com/search?q={}+docs".format(provider))
    return [
        "# No validated template for: {} | {} | {}".format(category, provider, service),
        "# Vuln ID: {}".format(vuln_id),
        "",
        "# TODO: Consult official {} documentation:".format(provider),
        "# {}".format(doc),
        "",
        "# Suggested CLI structure:",
        "# {} <service> <subcommand> \\".format(cli),
        "#   --identifier {{RESOURCE_ID}} \\",
        "#   --remediation-flag {{VALUE}}",
    ]


# Process entire DataFrame (called by app.py engine button)
def process_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    templates  = _load_templates()
    output_dir = Path(__file__).resolve().parent.parent / "scripts_output"
    output_dir.mkdir(exist_ok=True)

    results = []
    for _, row in df.iterrows():
        result = generate_script(row, templates)
        fname  = output_dir / "remediate_{}_{}.sh".format(row["id"], row.get("service", "general"))
        fname.write_text(result["script_text"], encoding="utf-8")
        results.append({
            "template_key":   result["matched_key"],
            "script_title":   result["title"],
            "script_matched": result["matched"],
            "script_path":    str(fname),
            "precondition_conflict":      result["precondition_conflict"],
            "precondition_conflict_note": result["precondition_conflict_note"],
        })

    extras = pd.DataFrame(results, index=df.index)
    return pd.concat([df, extras], axis=1)


# Built-in templates (category|provider based on real dataset categories)
_BUILTIN_TEMPLATES = {

    # ACCESS CONTROL
    "ACCESS_CONTROL|AWS": {
        "title": "Remediate AWS Access Control Misconfiguration",
        "description": "Enforce least-privilege IAM policies, remove wildcards, enable MFA.",
        "commands": [
            "# Step 1: List all policies with wildcard actions",
            "aws iam list-policies --scope Local --output table",
            "",
            "# Step 2: Identify and remove wildcard (*) permissions",
            "aws iam get-policy-version \\",
            "  --policy-arn {{POLICY_ARN}} \\",
            "  --version-id v1 --output json",
            "",
            "# Step 3: Create restricted replacement policy",
            "aws iam create-policy-version \\",
            "  --policy-arn {{POLICY_ARN}} \\",
            "  --policy-document file://restricted-policy.json \\",
            "  --set-as-default",
            "",
            "# Step 4: Enable MFA enforcement via SCP",
            "aws organizations create-policy \\",
            "  --name EnforceMFA \\",
            "  --type SERVICE_CONTROL_POLICY \\",
            "  --content file://enforce-mfa-scp.json",
            "",
            "# Step 5: Audit all IAM users for excess permissions",
            "aws iam generate-credential-report",
            "aws iam get-credential-report --query Content --output text | base64 -d",
        ]
    },
    "ACCESS_CONTROL|AZURE": {
        "title": "Remediate Azure Access Control Misconfiguration",
        "description": "Remove overly permissive role assignments and enforce RBAC least privilege.",
        "commands": [
            "# Step 1: List all role assignments at subscription scope",
            "az role assignment list --all --output table",
            "",
            "# Step 2: Remove Owner/Contributor at subscription scope",
            "az role assignment delete \\",
            "  --assignee {{SERVICE_PRINCIPAL_ID}} \\",
            "  --role Owner \\",
            "  --scope /subscriptions/{{SUBSCRIPTION_ID}}",
            "",
            "# Step 3: Re-assign least-privilege role at resource group scope",
            "az role assignment create \\",
            "  --assignee {{SERVICE_PRINCIPAL_ID}} \\",
            "  --role Reader \\",
            "  --scope /subscriptions/{{SUBSCRIPTION_ID}}/resourceGroups/{{RG_NAME}}",
            "",
            "# Step 4: Enable Privileged Identity Management (PIM)",
            "az rest --method POST \\",
            "  --url https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/{{REQUEST_ID}}?api-version=2020-10-01",
        ]
    },
    "ACCESS_CONTROL|GCP": {
        "title": "Remediate GCP Access Control Misconfiguration",
        "description": "Remove primitive roles and enforce custom least-privilege IAM.",
        "commands": [
            "# Step 1: List all IAM bindings on the project",
            "gcloud projects get-iam-policy {{PROJECT_ID}} --format=json",
            "",
            "# Step 2: Remove primitive Editor/Owner role",
            "gcloud projects remove-iam-policy-binding {{PROJECT_ID}} \\",
            "  --member=serviceAccount:{{SA_EMAIL}} \\",
            "  --role=roles/editor",
            "",
            "# Step 3: Grant least-privilege custom role",
            "gcloud projects add-iam-policy-binding {{PROJECT_ID}} \\",
            "  --member=serviceAccount:{{SA_EMAIL}} \\",
            "  --role=roles/viewer",
            "",
            "# Step 4: Verify final bindings",
            "gcloud projects get-iam-policy {{PROJECT_ID}} \\",
            "  --flatten=bindings --format=table",
        ]
    },

    # AUTHENTICATION
    "AUTHENTICATION|AWS": {
        "title": "Remediate AWS Authentication Weakness",
        "description": "Enforce MFA, rotate credentials, delete root access keys.",
        "commands": [
            "# Step 1: Delete root account access keys",
            "aws iam list-access-keys --user-name root",
            "aws iam update-access-key \\",
            "  --access-key-id {{ACCESS_KEY_ID}} \\",
            "  --status Inactive",
            "aws iam delete-access-key \\",
            "  --access-key-id {{ACCESS_KEY_ID}}",
            "",
            "# Step 2: Enforce MFA for all IAM users",
            "aws iam update-account-password-policy \\",
            "  --minimum-password-length 14 \\",
            "  --require-symbols --require-numbers \\",
            "  --require-uppercase-characters \\",
            "  --max-password-age 90",
            "",
            "# Step 3: Enable GuardDuty for anomaly detection",
            "aws guardduty create-detector --enable",
            "",
            "# Step 4: Rotate all active access keys",
            "aws iam list-users --query Users[*].UserName --output text | \\",
            "  xargs -I{} aws iam list-access-keys --user-name {}",
        ]
    },
    "AUTHENTICATION|AZURE": {
        "title": "Remediate Azure Authentication Weakness",
        "description": "Enable MFA, enforce conditional access, disable legacy authentication.",
        "commands": [
            "# Step 1: Enable MFA for all users via Conditional Access",
            "az ad conditional-access policy create \\",
            "  --name RequireMFA \\",
            "  --state enabled",
            "",
            "# Step 2: Block legacy authentication protocols",
            "az ad conditional-access policy create \\",
            "  --name BlockLegacyAuth \\",
            "  --conditions '{\"clientAppTypes\":[\"exchangeActiveSync\",\"other\"]}' \\",
            "  --grant-controls '{\"operator\":\"OR\",\"builtInControls\":[\"block\"]}'",
            "",
            "# Step 3: Enable Identity Protection",
            "az security setting update \\",
            "  --name MCAS \\",
            "  --enabled true",
            "",
            "# Step 4: Audit sign-in logs for suspicious activity",
            "az monitor activity-log list \\",
            "  --filter category eq SignInLogs \\",
            "  --output table",
        ]
    },

    # PRIVILEGE ESCALATION
    "PRIVILEGE_ESCALATION|AWS": {
        "title": "Remediate AWS Privilege Escalation Path",
        "description": "Remove IAM actions that allow privilege escalation (iam:PassRole, sts:AssumeRole).",
        "commands": [
            "# Step 1: Identify roles with iam:PassRole or sts:AssumeRole",
            "aws iam list-policies --scope Local | jq '.Policies[].Arn' | \\",
            "  xargs -I{} aws iam get-policy-version --policy-arn {} --version-id v1",
            "",
            "# Step 2: Remove dangerous IAM actions from policy",
            "# Edit your policy JSON to remove: iam:PassRole, iam:CreatePolicyVersion,",
            "# iam:AttachRolePolicy, sts:AssumeRole with wildcard resources",
            "aws iam create-policy-version \\",
            "  --policy-arn {{POLICY_ARN}} \\",
            "  --policy-document file://safe-policy.json \\",
            "  --set-as-default",
            "",
            "# Step 3: Enable AWS IAM Access Analyzer",
            "aws accessanalyzer create-analyzer \\",
            "  --analyzer-name PrivEscAnalyzer \\",
            "  --type ACCOUNT",
            "",
            "# Step 4: Verify no privilege escalation paths remain",
            "aws accessanalyzer list-findings \\",
            "  --analyzer-arn {{ANALYZER_ARN}} \\",
            "  --output table",
        ]
    },
    "PRIVILEGE_ESCALATION|AZURE": {
        "title": "Remediate Azure Privilege Escalation",
        "description": "Remove dangerous role assignments and restrict PIM eligibility.",
        "commands": [
            "# Step 1: Audit all Owner/Contributor assignments",
            "az role assignment list \\",
            "  --role Owner --all --output table",
            "",
            "# Step 2: Remove direct Owner assignments",
            "az role assignment delete \\",
            "  --assignee {{PRINCIPAL_ID}} \\",
            "  --role Owner \\",
            "  --scope {{SCOPE}}",
            "",
            "# Step 3: List current permanent-vs-PIM-eligible role assignment schedules.",
            "# This is a read-only audit step - it does not itself enforce anything.",
            "az rest --method GET \\",
            "  --url https://management.azure.com/providers/Microsoft.Authorization/roleAssignmentSchedules?api-version=2020-10-01",
            "",
            "# Step 4: Convert a remaining permanent Owner assignment to a time-bound",
            "# PIM-eligible assignment. The request body's schedule/justification",
            "# fields must be authored by the reviewer - there is no safe default here.",
            "az rest --method PUT \\",
            "  --url https://management.azure.com/{{SCOPE}}/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/{{REQUEST_GUID}}?api-version=2020-10-01 \\",
            "  --body '{{PIM_ELIGIBILITY_REQUEST_BODY}}'",
            "",
            "# Step 5: Enable Microsoft Defender for Resource Manager - flags anomalous",
            "# role-assignment / ARM control-plane activity (Defender for Identity is a",
            "# separate product not managed via `az security pricing`).",
            "az security pricing create \\",
            "  --name Arm --tier Standard",
        ]
    },
    "PRIVILEGE_ESCALATION|GCP": {
        "title": "Remediate GCP Privilege Escalation",
        "description": "Remove project-level primitive roles and restrict service account impersonation.",
        "commands": [
            "# Step 1: List all project-level IAM bindings",
            "gcloud projects get-iam-policy {{PROJECT_ID}}",
            "",
            "# Step 2: Remove primitive roles (owner, editor)",
            "gcloud projects remove-iam-policy-binding {{PROJECT_ID}} \\",
            "  --member=serviceAccount:{{SA_EMAIL}} \\",
            "  --role=roles/owner",
            "",
            "# Step 3: Disable service account key creation",
            "gcloud resource-manager org-policies set-policy \\",
            "  --organization={{ORG_ID}} \\",
            "  disable-service-account-key-creation-policy.json",
            "",
            "# Step 4: Enable Security Command Center",
            "gcloud services enable securitycenter.googleapis.com",
        ]
    },

    # DATA-PLANE PUBLIC/WILDCARD ACCESS (routed here via vulnerable_code,
    # not category - see _vulnerable_code_override_keys)
    "DATA_PLANE_PUBLIC_ACCESS|AWS": {
        "title": "Remediate AWS Data-Plane Public/Wildcard Access",
        "description": ("Remove a wildcard Principal grant on a data-plane resource "
                         "(bucket policy, etc.) - distinct from an IAM/RBAC role "
                         "privilege-escalation fix."),
        "commands": [
            "# Step 1: Retrieve the current bucket policy to find the wildcard statement",
            "aws s3api get-bucket-policy --bucket {{BUCKET_NAME}} --output text",
            "",
            "# Step 2: Replace the wildcard Principal with the specific principal(s)/",
            "# role ARN(s) that legitimately need access, then apply the corrected policy",
            "aws s3api put-bucket-policy \\",
            "  --bucket {{BUCKET_NAME}} \\",
            "  --policy file://{{SAFE_POLICY_JSON}}",
            "",
            "# Step 3: Block public access at the bucket level as defense-in-depth",
            "aws s3api put-public-access-block \\",
            "  --bucket {{BUCKET_NAME}} \\",
            "  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        ]
    },
    "DATA_PLANE_PUBLIC_ACCESS|AZURE": {
        "title": "Remediate Azure Data-Plane Public/Wildcard ACL Access",
        "description": ("Remove a wildcard/AnyUser ACL entry on a Storage/Data Lake "
                         "resource - distinct from a control-plane RBAC role-assignment fix."),
        "commands": [
            "# Step 1: List current ACL entries on the container/filesystem path",
            "az storage fs access show \\",
            "  --account-name {{STORAGE_ACCOUNT}} \\",
            "  -f {{FILESYSTEM_NAME}} -p {{PATH}}",
            "",
            "# Step 2: Remove the wildcard/AnyUser ACL entry and grant the specific",
            "# principal(s) that legitimately need access",
            "az storage fs access set \\",
            "  --account-name {{STORAGE_ACCOUNT}} \\",
            "  -f {{FILESYSTEM_NAME}} -p {{PATH}} \\",
            "  --acl \"user:{{PRINCIPAL_ID}}:r-x\"",
            "",
            "# Step 3: Disable anonymous/public blob access at the storage account level",
            "az storage account update \\",
            "  --name {{STORAGE_ACCOUNT}} \\",
            "  --resource-group {{RG_NAME}} \\",
            "  --allow-blob-public-access false",
        ]
    },
    "DATA_PLANE_PUBLIC_ACCESS|GCP": {
        "title": "Remediate GCP Data-Plane Public/Wildcard IAM Binding",
        "description": ("Remove an allUsers/allAuthenticatedUsers IAM binding on a "
                         "data-plane resource (bucket, Cloud Run, function) - distinct "
                         "from a project-level role privilege-escalation fix."),
        "commands": [
            "# Step 1: List current IAM policy bindings on the resource",
            "gcloud storage buckets get-iam-policy gs://{{BUCKET_NAME}}",
            "",
            "# Step 2: Remove the public/wildcard member binding",
            "gcloud storage buckets remove-iam-policy-binding gs://{{BUCKET_NAME}} \\",
            "  --member=allUsers \\",
            "  --role={{ROLE}}",
            "",
            "# Step 3: If this is a Cloud Run / Cloud Function service, also remove",
            "# unauthenticated-invoker access",
            "gcloud run services remove-iam-policy-binding {{SERVICE_NAME}} \\",
            "  --member=allUsers \\",
            "  --role=roles/run.invoker \\",
            "  --region={{REGION}}",
        ]
    },

    # DATA EXPOSURE
    "DATA_EXPOSURE|AWS": {
        "title": "Remediate AWS Data Exposure",
        "description": "Block public access on S3, enable encryption, restrict data access.",
        "commands": [
            "# Step 1: Block all S3 public access",
            "aws s3api put-public-access-block \\",
            "  --bucket {{BUCKET_NAME}} \\",
            "  --public-access-block-configuration \\",
            "  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            "",
            "# Step 2: Enable S3 server-side encryption",
            "aws s3api put-bucket-encryption \\",
            "  --bucket {{BUCKET_NAME}} \\",
            "  --server-side-encryption-configuration \\",
            "  '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
            "",
            "# Step 3: Enable CloudTrail logging",
            "aws cloudtrail create-trail \\",
            "  --name DataAuditTrail \\",
            "  --s3-bucket-name {{LOG_BUCKET}} \\",
            "  --is-multi-region-trail",
            "aws cloudtrail start-logging --name DataAuditTrail",
            "",
            "# Step 4: Enable Macie for sensitive data discovery",
            "aws macie2 enable-macie",
            "aws macie2 create-classification-job \\",
            "  --job-type ONE_TIME \\",
            "  --s3-job-definition '{\"bucketDefinitions\":[{\"accountId\":\"{{ACCOUNT_ID}}\",\"buckets\":[\"{{BUCKET_NAME}}\"]}]}'",
        ]
    },
    "DATA_EXPOSURE|AZURE": {
        "title": "Remediate Azure Data Exposure",
        "description": "Disable public blob access, enable encryption, restrict storage access.",
        "commands": [
            "# Step 1: Disable public blob access",
            "az storage account update \\",
            "  --name {{STORAGE_ACCOUNT}} \\",
            "  --resource-group {{RG_NAME}} \\",
            "  --allow-blob-public-access false",
            "",
            "# Step 2: Enable storage encryption",
            "az storage account update \\",
            "  --name {{STORAGE_ACCOUNT}} \\",
            "  --resource-group {{RG_NAME}} \\",
            "  --encryption-services blob file",
            "",
            "# Step 3: Enable Defender for Storage",
            "az security pricing create \\",
            "  --name StorageAccounts --tier Standard",
            "",
            "# Step 4: Set up diagnostic logging",
            "az monitor diagnostic-settings create \\",
            "  --name storage-audit \\",
            "  --resource {{STORAGE_ACCOUNT_ID}} \\",
            "  --logs '[{\"category\":\"StorageRead\",\"enabled\":true},{\"category\":\"StorageWrite\",\"enabled\":true}]'",
        ]
    },
    "DATA_EXPOSURE|GCP": {
        "title": "Remediate GCP Data Exposure",
        "description": "Remove allUsers/allAuthenticatedUsers access from Cloud Storage buckets.",
        "commands": [
            "# Step 1: Remove public access from bucket",
            "gsutil iam ch -d allUsers:objectViewer gs://{{BUCKET_NAME}}",
            "gsutil iam ch -d allAuthenticatedUsers:objectViewer gs://{{BUCKET_NAME}}",
            "",
            "# Step 2: Enable uniform bucket-level access",
            "gsutil uniformbucketlevelaccess set on gs://{{BUCKET_NAME}}",
            "",
            "# Step 3: Enable Cloud Audit Logs",
            "gcloud projects set-iam-policy {{PROJECT_ID}} audit-policy.json",
            "",
            "# Step 4: Enable DLP for sensitive data scanning",
            "gcloud services enable dlp.googleapis.com",
        ]
    },

    # NETWORK SECURITY
    "NETWORK_SECURITY|AWS": {
        "title": "Remediate AWS Network Security Misconfiguration",
        "description": "Remove unrestricted security group rules, enable VPC flow logs.",
        "commands": [
            "# Step 1: List all security groups with 0.0.0.0/0 ingress",
            "aws ec2 describe-security-groups \\",
            "  --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \\",
            "  --query SecurityGroups[*].[GroupId,GroupName] --output table",
            "",
            "# Step 2: Revoke unrestricted inbound rules",
            "aws ec2 revoke-security-group-ingress \\",
            "  --group-id {{SG_ID}} \\",
            "  --protocol tcp --port {{PORT}} --cidr 0.0.0.0/0",
            "",
            "# Step 3: Add restricted ingress from trusted CIDR only",
            "aws ec2 authorize-security-group-ingress \\",
            "  --group-id {{SG_ID}} \\",
            "  --protocol tcp --port {{PORT}} \\",
            "  --cidr {{TRUSTED_CIDR}}/32",
            "",
            "# Step 4: Enable VPC Flow Logs",
            "aws ec2 create-flow-logs \\",
            "  --resource-type VPC \\",
            "  --resource-ids {{VPC_ID}} \\",
            "  --traffic-type ALL \\",
            "  --log-destination-type cloud-watch-logs \\",
            "  --log-group-name VPCFlowLogs",
        ]
    },
    "NETWORK_SECURITY|AZURE": {
        "title": "Remediate Azure Network Security Misconfiguration",
        "description": "Remove overly permissive NSG rules and enable Network Watcher.",
        "commands": [
            "# Step 1: List all NSG rules allowing Any source",
            "az network nsg rule list \\",
            "  --resource-group {{RG_NAME}} \\",
            "  --nsg-name {{NSG_NAME}} \\",
            "  --query \"[?sourceAddressPrefix=='*']\" --output table",
            "",
            "# Step 2: Delete overly permissive rule",
            "az network nsg rule delete \\",
            "  --resource-group {{RG_NAME}} \\",
            "  --nsg-name {{NSG_NAME}} \\",
            "  --name {{RULE_NAME}}",
            "",
            "# Step 3: Add restricted rule from trusted IP",
            "az network nsg rule create \\",
            "  --resource-group {{RG_NAME}} \\",
            "  --nsg-name {{NSG_NAME}} \\",
            "  --name AllowTrustedOnly \\",
            "  --priority 100 --direction Inbound --access Allow \\",
            "  --protocol Tcp \\",
            "  --source-address-prefixes {{TRUSTED_IP}}/32 \\",
            "  --destination-port-ranges {{PORT}}",
            "",
            "# Step 4: Enable Network Watcher flow logs",
            "az network watcher flow-log create \\",
            "  --name FlowLog --nsg {{NSG_NAME}} \\",
            "  --resource-group {{RG_NAME}} \\",
            "  --storage-account {{STORAGE_ACCOUNT}} --enabled true",
        ]
    },

    "NETWORK_SECURITY|GCP": {
        "title": "Remediate GCP Network Security Misconfiguration",
        "description": "Remove overly permissive firewall rules and restrict ingress to trusted ranges.",
        "commands": [
            "# Step 1: List firewall rules allowing 0.0.0.0/0 ingress",
            "gcloud compute firewall-rules list \\",
            "  --filter=\"sourceRanges:('0.0.0.0/0')\" --format table",
            "",
            "# Step 2: Update the rule to a trusted CIDR only",
            "gcloud compute firewall-rules update {{RULE_NAME}} \\",
            "  --source-ranges={{TRUSTED_CIDR}}/32",
            "",
            "# Step 3: Enable VPC Flow Logs on the subnet",
            "gcloud compute networks subnets update {{SUBNET_NAME}} \\",
            "  --region={{REGION}} --enable-flow-logs",
            "",
            "# Step 4: Verify final firewall ruleset",
            "gcloud compute firewall-rules describe {{RULE_NAME}}",
        ]
    },

    # ENCRYPTION
    "ENCRYPTION|AWS": {
        "title": "Remediate AWS Encryption Misconfiguration",
        "description": "Enable KMS key rotation, enforce encryption at rest and in transit.",
        "commands": [
            "# Step 1: Enable KMS key rotation",
            "aws kms enable-key-rotation --key-id {{KEY_ID}}",
            "aws kms get-key-rotation-status --key-id {{KEY_ID}}",
            "",
            "# Step 2: Enforce S3 encryption via bucket policy",
            "aws s3api put-bucket-policy \\",
            "  --bucket {{BUCKET_NAME}} \\",
            "  --policy file://enforce-encryption-policy.json",
            "",
            "# Step 3: Enable RDS encryption (requires snapshot restore)",
            "aws rds create-db-snapshot \\",
            "  --db-instance-identifier {{DB_ID}} \\",
            "  --db-snapshot-identifier {{DB_ID}}-encrypted-snap",
            "",
            "# Step 4: Enforce HTTPS-only on API Gateway",
            "aws apigateway update-rest-api \\",
            "  --rest-api-id {{API_ID}} \\",
            "  --patch-operations op=replace,path=/minimumCompressionSize,value=0",
        ]
    },
    "ENCRYPTION|AZURE": {
        "title": "Remediate Azure Encryption Misconfiguration",
        "description": "Enable Key Vault protection, enforce encryption, enable soft-delete.",
        "commands": [
            "# Step 1: Enable Key Vault soft delete and purge protection",
            "az keyvault update \\",
            "  --name {{KEYVAULT_NAME}} \\",
            "  --resource-group {{RG_NAME}} \\",
            "  --enable-soft-delete true \\",
            "  --enable-purge-protection true",
            "",
            "# Step 2: Rotate Key Vault keys",
            "az keyvault key create \\",
            "  --vault-name {{KEYVAULT_NAME}} \\",
            "  --name {{KEY_NAME}} \\",
            "  --protection software",
            "",
            "# Step 3: Enable disk encryption",
            "az vm encryption enable \\",
            "  --resource-group {{RG_NAME}} \\",
            "  --name {{VM_NAME}} \\",
            "  --disk-encryption-keyvault {{KEYVAULT_NAME}}",
            "",
            "# Step 4: Audit Key Vault access",
            "az monitor diagnostic-settings create \\",
            "  --name kv-audit \\",
            "  --resource $(az keyvault show -n {{KEYVAULT_NAME}} --query id -o tsv) \\",
            "  --logs '[{\"category\":\"AuditEvent\",\"enabled\":true}]'",
        ]
    },

    # DATA EXFILTRATION
    "DATA_EXFILTRATION|AWS": {
        "title": "Remediate AWS Data Exfiltration Risk",
        "description": "Block outbound data transfer paths, enable GuardDuty and Macie.",
        "commands": [
            "# Step 1: Enable GuardDuty (detects exfiltration attempts)",
            "aws guardduty create-detector --enable",
            "",
            "# Step 2: Block public S3 access account-wide",
            "aws s3control put-public-access-block \\",
            "  --account-id {{ACCOUNT_ID}} \\",
            "  --public-access-block-configuration \\",
            "  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            "",
            "# Step 3: Enable Macie for sensitive data monitoring",
            "aws macie2 enable-macie",
            "",
            "# Step 4: Apply SCP to deny s3:GetObject from outside org",
            "aws organizations create-policy \\",
            "  --name DenyExternalS3Access \\",
            "  --type SERVICE_CONTROL_POLICY \\",
            "  --content file://deny-external-s3.json",
        ]
    },

    # DENIAL OF SERVICE
    "DENIAL_OF_SERVICE|AWS": {
        "title": "Remediate AWS Denial of Service Exposure",
        "description": "Enable AWS Shield, WAF rate limiting, and Auto Scaling protections.",
        "commands": [
            "# Step 1: Enable AWS Shield Standard (free, automatic)",
            "aws shield describe-subscription",
            "",
            "# Step 2: Create WAF rate-based rule",
            "aws wafv2 create-web-acl \\",
            "  --name RateLimitACL \\",
            "  --scope REGIONAL \\",
            "  --default-action Allow={} \\",
            "  --rules file://rate-limit-rules.json \\",
            "  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=RateLimitACL",
            "",
            "# Step 3: Configure Auto Scaling with scale-in protection",
            "aws autoscaling put-scaling-policy \\",
            "  --auto-scaling-group-name {{ASG_NAME}} \\",
            "  --policy-name ScaleOutPolicy \\",
            "  --policy-type TargetTrackingScaling \\",
            "  --target-tracking-configuration file://target-tracking.json",
            "",
            "# Step 4: Enable CloudFront with DDoS protection",
            "aws cloudfront create-distribution \\",
            "  --distribution-config file://cloudfront-config.json",
        ]
    },

    # CODE INJECTION
    "CODE_INJECTION|AWS": {
        "title": "Remediate AWS Code Injection Vulnerability",
        "description": "Enable WAF, restrict Lambda permissions, validate inputs via parameter validation.",
        "commands": [
            "# Step 1: Attach WAF to API Gateway / ALB",
            "aws wafv2 associate-web-acl \\",
            "  --web-acl-arn {{WAF_ACL_ARN}} \\",
            "  --resource-arn {{API_GATEWAY_ARN}}",
            "",
            "# Step 2: Enable AWS managed rule groups (SQL injection, XSS)",
            "# Add to WAF ACL rules: AWSManagedRulesSQLiRuleSet, AWSManagedRulesCommonRuleSet",
            "",
            "# Step 3: Restrict Lambda execution role",
            "aws iam update-role \\",
            "  --role-name {{LAMBDA_ROLE}} \\",
            "  --description Least-privilege Lambda role",
            "",
            "# Step 4: Enable Lambda code signing",
            "aws lambda put-function-code-signing-config \\",
            "  --function-name {{FUNCTION_NAME}} \\",
            "  --code-signing-config-arn {{CODE_SIGNING_ARN}}",
        ]
    },
    "CODE_INJECTION|AZURE": {
        "title": "Remediate Azure Code Injection Vulnerability",
        "description": "Attach WAF policy to Front Door/App Gateway and enable managed rule sets.",
        "commands": [
            "# Step 1: Enable WAF on Application Gateway",
            "az network application-gateway waf-config set \\",
            "  --gateway-name {{APPGW_NAME}} --resource-group {{RG_NAME}} \\",
            "  --enabled true --firewall-mode Prevention",
            "",
            "# Step 2: Enable OWASP managed rule set (SQLi / XSS)",
            "az network application-gateway waf-policy managed-rule rule-set add \\",
            "  --policy-name {{WAF_POLICY}} --resource-group {{RG_NAME}} \\",
            "  --type OWASP --version 3.2",
            "",
            "# Step 3: Restrict Function App execution identity",
            "az functionapp identity assign --name {{FUNCTION_APP}} --resource-group {{RG_NAME}}",
        ]
    },
    "CODE_INJECTION|GCP": {
        "title": "Remediate GCP Code Injection Vulnerability",
        "description": "Enable Cloud Armor WAF rules and restrict Cloud Function invoker permissions.",
        "commands": [
            "# Step 1: Create Cloud Armor security policy with OWASP rules",
            "gcloud compute security-policies create {{POLICY_NAME}} \\",
            "  --description 'Blocks SQLi/XSS'",
            "gcloud compute security-policies rules create 1000 \\",
            "  --security-policy {{POLICY_NAME}} \\",
            "  --expression \"evaluatePreconfiguredExpr('sqli-stable')\" --action deny-403",
            "",
            "# Step 2: Restrict Cloud Function invoker to authenticated only",
            "gcloud functions remove-iam-policy-binding {{FUNCTION_NAME}} \\",
            "  --member=allUsers --role=roles/cloudfunctions.invoker",
        ]
    },

    # AUTHENTICATION (GCP gap-fill)
    "AUTHENTICATION|GCP": {
        "title": "Remediate GCP Authentication Weakness",
        "description": "Enforce 2-Step Verification via org policy and rotate exposed service-account keys.",
        "commands": [
            "# Step 1: List service account keys older than 90 days",
            "gcloud iam service-accounts keys list \\",
            "  --iam-account={{SA_EMAIL}} --managed-by=user",
            "",
            "# Step 2: Delete the exposed/legacy key",
            "gcloud iam service-accounts keys delete {{KEY_ID}} \\",
            "  --iam-account={{SA_EMAIL}}",
            "",
            "# Step 3: Enforce org-wide 2-Step Verification",
            "gcloud resource-manager org-policies set-policy \\",
            "  --organization={{ORG_ID}} \\",
            "  enforce-2sv-policy.json",
            "",
            "# Step 4: Enable Identity-Aware Proxy for sensitive services",
            "gcloud services enable iap.googleapis.com",
        ]
    },

    # ENCRYPTION (GCP gap-fill)
    "ENCRYPTION|GCP": {
        "title": "Remediate GCP Encryption Misconfiguration",
        "description": "Rotate Cloud KMS keys and enforce CMEK on storage/database resources.",
        "commands": [
            "# Step 1: Set automatic KMS key rotation (90 days)",
            "gcloud kms keys update {{KEY_NAME}} \\",
            "  --keyring={{KEYRING}} --location={{LOCATION}} \\",
            "  --rotation-period=90d --next-rotation-time=+p90d",
            "",
            "# Step 2: Enforce customer-managed encryption keys on the bucket",
            "gcloud storage buckets update gs://{{BUCKET_NAME}} \\",
            "  --default-encryption-key={{KMS_KEY_RESOURCE}}",
            "",
            "# Step 3: Verify encryption configuration",
            "gcloud kms keys describe {{KEY_NAME}} \\",
            "  --keyring={{KEYRING}} --location={{LOCATION}}",
        ]
    },

    # DATA EXFILTRATION (Azure/GCP gap-fill)
    "DATA_EXFILTRATION|AZURE": {
        "title": "Remediate Azure Data Exfiltration Risk",
        "description": "Enable Defender for Cloud, restrict outbound NSG rules, enable Private Link.",
        "commands": [
            "# Step 1: Enable Microsoft Defender for Cloud (all plans)",
            "az security pricing create --name StorageAccounts --tier Standard",
            "",
            "# Step 2: Restrict outbound traffic on NSG to approved endpoints only",
            "az network nsg rule create \\",
            "  --resource-group {{RG_NAME}} --nsg-name {{NSG_NAME}} \\",
            "  --name DenyAllOutbound --priority 4096 \\",
            "  --direction Outbound --access Deny --protocol '*' \\",
            "  --destination-address-prefixes '*'",
            "",
            "# Step 3: Enable Private Link for storage/database access",
            "az network private-endpoint create \\",
            "  --name {{PE_NAME}} --resource-group {{RG_NAME}} \\",
            "  --vnet-name {{VNET_NAME}} --subnet {{SUBNET_NAME}} \\",
            "  --private-connection-resource-id {{RESOURCE_ID}} \\",
            "  --group-id blob --connection-name {{CONNECTION_NAME}}",
        ]
    },
    "DATA_EXFILTRATION|GCP": {
        "title": "Remediate GCP Data Exfiltration Risk",
        "description": "Enable VPC Service Controls and Cloud DLP to contain and detect exfiltration.",
        "commands": [
            "# Step 1: Create a VPC Service Controls perimeter",
            "gcloud access-context-manager perimeters create {{PERIMETER_NAME}} \\",
            "  --policy={{POLICY_ID}} --resources=projects/{{PROJECT_NUMBER}} \\",
            "  --restricted-services=storage.googleapis.com,bigquery.googleapis.com",
            "",
            "# Step 2: Enable Cloud DLP inspection job on sensitive datasets",
            "gcloud services enable dlp.googleapis.com",
            "",
            "# Step 3: Enable VPC Flow Logs for egress monitoring",
            "gcloud compute networks subnets update {{SUBNET_NAME}} \\",
            "  --region={{REGION}} --enable-flow-logs",
        ]
    },

    # DENIAL OF SERVICE (Azure/GCP gap-fill)
    "DENIAL_OF_SERVICE|AZURE": {
        "title": "Remediate Azure Denial of Service Exposure",
        "description": "Enable Azure DDoS Protection and WAF rate limiting.",
        "commands": [
            "# Step 1: Enable DDoS Protection Standard on the VNet",
            "az network ddos-protection create \\",
            "  --resource-group {{RG_NAME}} --name {{DDOS_PLAN_NAME}}",
            "",
            "# Step 2: Add a rate-limit custom rule to the WAF policy",
            "az network application-gateway waf-policy custom-rule create \\",
            "  --policy-name {{WAF_POLICY}} --resource-group {{RG_NAME}} \\",
            "  --name RateLimitRule --priority 1 --rule-type RateLimitRule \\",
            "  --rate-limit-threshold 100 --action Block",
            "",
            "# Step 3: Configure autoscale to absorb legitimate traffic spikes",
            "az monitor autoscale create \\",
            "  --resource-group {{RG_NAME}} --resource {{VMSS_ID}} \\",
            "  --min-count 2 --max-count 10 --count 2",
        ]
    },
    "DENIAL_OF_SERVICE|GCP": {
        "title": "Remediate GCP Denial of Service Exposure",
        "description": "Enable Cloud Armor rate limiting and Managed Instance Group autoscaling.",
        "commands": [
            "# Step 1: Add a rate-based ban rule to Cloud Armor policy",
            "gcloud compute security-policies rules create 2000 \\",
            "  --security-policy {{POLICY_NAME}} \\",
            "  --action=rate-based-ban --rate-limit-threshold-count=100 \\",
            "  --rate-limit-threshold-interval-sec=60 --ban-duration-sec=600",
            "",
            "# Step 2: Enable autoscaling on the Managed Instance Group",
            "gcloud compute instance-groups managed set-autoscaling {{MIG_NAME}} \\",
            "  --zone={{ZONE}} --min-num-replicas=2 --max-num-replicas=10 \\",
            "  --target-cpu-utilization=0.7",
        ]
    },

    # SESSION MANAGEMENT
    "SESSION_MANAGEMENT|AWS": {
        "title": "Remediate AWS Session Management Weakness",
        "description": "Enforce short-lived tokens, revoke stale sessions, enable session logging.",
        "commands": [
            "# Step 1: Reduce Cognito/STS token lifetime",
            "aws cognito-idp update-user-pool-client \\",
            "  --user-pool-id {{POOL_ID}} --client-id {{CLIENT_ID}} \\",
            "  --access-token-validity 15 --id-token-validity 15",
            "",
            "# Step 2: Revoke all active refresh tokens for the affected user",
            "aws cognito-idp admin-user-global-sign-out \\",
            "  --user-pool-id {{POOL_ID}} --username {{USERNAME}}",
            "",
            "# Step 3: Enable CloudTrail logging for session/auth events",
            "aws cloudtrail start-logging --name {{TRAIL_NAME}}",
        ]
    },
    "SESSION_MANAGEMENT|AZURE": {
        "title": "Remediate Azure Session Management Weakness",
        "description": "Enforce sign-in frequency controls and revoke stale refresh tokens.",
        "commands": [
            "# Step 1: Set a sign-in frequency conditional access control",
            "az ad conditional-access policy create \\",
            "  --name EnforceSignInFrequency \\",
            "  --session-controls '{\"signInFrequency\":{\"value\":1,\"type\":\"hours\",\"isEnabled\":true}}'",
            "",
            "# Step 2: Revoke all active refresh tokens for the affected user",
            "az ad user revoke-sign-in-sessions --id {{USER_ID}}",
        ]
    },
    "SESSION_MANAGEMENT|GCP": {
        "title": "Remediate GCP Session Management Weakness",
        "description": "Shorten session length via Context-Aware Access and revoke active sessions.",
        "commands": [
            "# Step 1: Set a shorter Google session length for the org",
            "gcloud resource-manager org-policies set-policy \\",
            "  --organization={{ORG_ID}} \\",
            "  session-length-policy.json",
            "",
            "# Step 2: Revoke a user's active OAuth/session tokens",
            "gcloud identity groups memberships delete \\",
            "  --group-email={{GROUP_EMAIL}} --member-email={{USER_EMAIL}}",
        ]
    },

    # DOMAIN HIJACKING
    "DOMAIN_HIJACKING|AWS": {
        "title": "Remediate AWS Domain Hijacking Risk (Route 53)",
        "description": "Lock the domain registrar, remove dangling DNS records, enable DNSSEC.",
        "commands": [
            "# Step 1: Enable registrar transfer lock",
            "aws route53domains enable-domain-transfer-lock --domain-name {{DOMAIN}}",
            "",
            "# Step 2: Remove dangling CNAME/alias records pointing to deprovisioned resources",
            "aws route53 change-resource-record-sets \\",
            "  --hosted-zone-id {{ZONE_ID}} \\",
            "  --change-batch file://remove-dangling-record.json",
            "",
            "# Step 3: Enable DNSSEC signing",
            "aws route53 enable-hosted-zone-dnssec --hosted-zone-id {{ZONE_ID}}",
        ]
    },
    "DOMAIN_HIJACKING|AZURE": {
        "title": "Remediate Azure Domain Hijacking Risk (Azure DNS)",
        "description": "Remove dangling DNS records and lock the DNS zone against unauthorized changes.",
        "commands": [
            "# Step 1: List CNAME records pointing to deprovisioned Azure resources",
            "az network dns record-set cname list \\",
            "  --resource-group {{RG_NAME}} --zone-name {{ZONE_NAME}}",
            "",
            "# Step 2: Remove the dangling record",
            "az network dns record-set cname remove-record \\",
            "  --resource-group {{RG_NAME}} --zone-name {{ZONE_NAME}} \\",
            "  --record-set-name {{RECORD_NAME}} --cname {{TARGET}}",
            "",
            "# Step 3: Apply a resource lock on the DNS zone",
            "az lock create --name DoNotDeleteDNS --resource-group {{RG_NAME}} \\",
            "  --resource-name {{ZONE_NAME}} --resource-type Microsoft.Network/dnszones \\",
            "  --lock-type CanNotDelete",
        ]
    },
    "DOMAIN_HIJACKING|GCP": {
        "title": "Remediate GCP Domain Hijacking Risk (Cloud DNS)",
        "description": "Remove dangling DNS records and enable DNSSEC on the managed zone.",
        "commands": [
            "# Step 1: List record sets for dangling references",
            "gcloud dns record-sets list --zone={{ZONE_NAME}}",
            "",
            "# Step 2: Remove the dangling record",
            "gcloud dns record-sets delete {{RECORD_NAME}} \\",
            "  --zone={{ZONE_NAME}} --type=CNAME",
            "",
            "# Step 3: Enable DNSSEC on the managed zone",
            "gcloud dns managed-zones update {{ZONE_NAME}} --dnssec-state=on",
        ]
    },

    # DATA LOSS
    "DATA_LOSS|AWS": {
        "title": "Remediate AWS Data Loss Risk",
        "description": "Enable versioning/backups and deletion protection to prevent unrecoverable data loss.",
        "commands": [
            "# Step 1: Enable S3 versioning on the affected bucket",
            "aws s3api put-bucket-versioning \\",
            "  --bucket {{BUCKET_NAME}} --versioning-configuration Status=Enabled",
            "",
            "# Step 2: Enable AWS Backup for the resource",
            "aws backup create-backup-plan --backup-plan file://backup-plan.json",
            "",
            "# Step 3: Enable deletion protection (RDS/DynamoDB)",
            "aws rds modify-db-instance \\",
            "  --db-instance-identifier {{DB_ID}} --deletion-protection",
        ]
    },
    "DATA_LOSS|AZURE": {
        "title": "Remediate Azure Data Loss Risk",
        "description": "Enable soft delete, blob versioning, and Azure Backup.",
        "commands": [
            "# Step 1: Enable blob soft delete and versioning",
            "az storage account blob-service-properties update \\",
            "  --account-name {{STORAGE_ACCOUNT}} --enable-versioning true \\",
            "  --enable-delete-retention true --delete-retention-days 30",
            "",
            "# Step 2: Configure Azure Backup for the resource",
            "az backup protection enable-for-vm \\",
            "  --resource-group {{RG_NAME}} --vault-name {{VAULT_NAME}} \\",
            "  --vm {{VM_NAME}} --policy-name DefaultPolicy",
        ]
    },
    "DATA_LOSS|GCP": {
        "title": "Remediate GCP Data Loss Risk",
        "description": "Enable Cloud Storage object versioning and scheduled backups.",
        "commands": [
            "# Step 1: Enable object versioning on the bucket",
            "gcloud storage buckets update gs://{{BUCKET_NAME}} --versioning",
            "",
            "# Step 2: Create a scheduled backup / snapshot policy",
            "gcloud compute resource-policies create snapshot-schedule {{SCHEDULE_NAME}} \\",
            "  --region={{REGION}} --daily-schedule --start-time=03:00",
        ]
    },

    # ORACLE CLOUD / IBM CLOUD / ALIBABA CLOUD
    "ACCESS_CONTROL|ORACLECLOUD": {
        "title": 'Remediate Oracle Cloud Access Control Misconfiguration',
        "description": 'Restrict overly-broad IAM policy statements and enforce least privilege.',
        "commands": [
            '# Step 1: List policies in the compartment',
            'oci iam policy list --compartment-id {{COMPARTMENT_ID}}',
            '',
            "# Step 2: Update the policy to remove 'manage all-resources' style statements",
            'oci iam policy update --policy-id {{resource}} \\',
            '  --statements \'["Allow group {{GROUP_NAME}} to read all-resources in compartment {{COMPARTMENT_NAME}}"]\'',
            '',
            '# Step 3: Verify updated statements',
            'oci iam policy get --policy-id {{resource}}',
        ]
    },
    "AUTHENTICATION|ORACLECLOUD": {
        "title": 'Remediate Oracle Cloud Authentication Weakness',
        "description": 'Remove stale API keys, enforce MFA on the affected IAM user.',
        "commands": [
            '# Step 1: List API signing keys for the user',
            'oci iam user api-key list --user-id {{USER_ID}}',
            '',
            '# Step 2: Delete the compromised/unused API key',
            'oci iam user api-key delete --user-id {{USER_ID}} --fingerprint {{KEY_FINGERPRINT}} --force',
            '',
            '# Step 3: Enforce MFA on the user',
            'oci iam mfa-totp-device create --user-id {{USER_ID}}',
        ]
    },
    "PRIVILEGE_ESCALATION|ORACLECLOUD": {
        "title": 'Remediate Oracle Cloud Privilege Escalation Path',
        "description": 'Remove the dynamic group / instance-principal policy granting excessive scope.',
        "commands": [
            '# Step 1: List dynamic groups and their matching rules',
            'oci iam dynamic-group list --compartment-id {{TENANCY_ID}}',
            '',
            '# Step 2: Narrow the matching rule to the specific resource only',
            'oci iam dynamic-group update --dynamic-group-id {{resource}} \\',
            '  --matching-rule "ANY {instance.id = \'{{INSTANCE_OCID}}\'}"',
            '',
            '# Step 3: Remove the over-privileged policy statement tied to the group',
            'oci iam policy update --policy-id {{POLICY_ID}} \\',
            '  --statements \'["Allow dynamic-group {{GROUP_NAME}} to read instance-family in compartment {{COMPARTMENT_NAME}}"]\'',
        ]
    },
    "DATA_EXPOSURE|ORACLECLOUD": {
        "title": 'Remediate Oracle Cloud Data Exposure',
        "description": 'Block public access on the Object Storage bucket and enable encryption.',
        "commands": [
            '# Step 1: Set the bucket visibility to private',
            'oci os bucket update --bucket-name {{resource}} --public-access-type NoPublicAccess',
            '',
            '# Step 2: Enable server-side encryption with a customer-managed key',
            'oci os bucket update --bucket-name {{resource}} --kms-key-id {{KMS_KEY_OCID}}',
            '',
            '# Step 3: Verify the bucket is no longer public',
            'oci os bucket get --bucket-name {{resource}} --query \'data."public-access-type"\'',
        ]
    },
    "NETWORK_SECURITY|ORACLECLOUD": {
        "title": 'Remediate Oracle Cloud Network Security Misconfiguration',
        "description": 'Remove the unrestricted ingress rule from the security list / NSG.',
        "commands": [
            '# Step 1: List current ingress rules on the security list',
            'oci network security-list get --security-list-id {{resource}}',
            '',
            '# Step 2: Update rules to remove 0.0.0.0/0 ingress on sensitive ports',
            'oci network security-list update --security-list-id {{resource}} \\',
            '  --ingress-security-rules file://restricted-ingress-rules.json',
            '',
            '# Step 3: Verify the updated rule set',
            'oci network security-list get --security-list-id {{resource}}',
        ]
    },
    "ENCRYPTION|ORACLECLOUD": {
        "title": 'Remediate Oracle Cloud Encryption Misconfiguration',
        "description": 'Enable automatic Vault key rotation for the customer-managed key.',
        "commands": [
            '# Step 1: Check current key rotation schedule',
            'oci kms management key get --key-id {{resource}} --endpoint {{KMS_MGMT_ENDPOINT}}',
            '',
            '# Step 2: Schedule automatic key rotation',
            'oci kms management key update --key-id {{resource}} \\',
            '  --endpoint {{KMS_MGMT_ENDPOINT}} --auto-key-rotation-details \'{"rotationIntervalInDays":365}\'',
        ]
    },
    "DATA_EXFILTRATION|ORACLECLOUD": {
        "title": 'Remediate Oracle Cloud Data Exfiltration Risk',
        "description": 'Restrict read access on the exposed resource and enable VCN flow logging.',
        "commands": [
            '# Step 1: Restrict the bucket/resource to authenticated principals only',
            'oci os bucket update --bucket-name {{resource}} --public-access-type NoPublicAccess',
            '',
            '# Step 2: Enable Service Connector Hub logging for exfil detection',
            'oci logging log create --log-group-id {{LOG_GROUP_ID}} --display-name vcn-flow-logs \\',
            '  --log-type SERVICE --configuration file://flow-log-config.json',
        ]
    },
    "DENIAL_OF_SERVICE|ORACLECLOUD": {
        "title": 'Remediate Oracle Cloud Denial of Service Exposure',
        "description": 'Enable WAF rate limiting and autoscaling on the affected instance pool.',
        "commands": [
            '# Step 1: Add a rate-limiting protection rule to the WAF policy',
            'oci waf web-app-firewall-policy request-rate-limiting-rule append \\',
            '  --web-app-firewall-policy-id {{WAF_POLICY_ID}} --name RateLimit --requests-limit 100',
            '',
            '# Step 2: Enable autoscaling on the instance pool',
            'oci autoscaling auto-scaling-configuration update \\',
            '  --auto-scaling-configuration-id {{ASG_ID}} --max-resource-count 10 --min-resource-count 2',
        ]
    },
    "CODE_INJECTION|ORACLECLOUD": {
        "title": 'Remediate Oracle Cloud Code Injection Vulnerability',
        "description": 'Enable OCI WAF SQLi/XSS protection rules in front of the application.',
        "commands": [
            '# Step 1: Enable the OWASP protection capabilities on the WAF policy',
            'oci waf web-app-firewall-policy protection-update \\',
            '  --web-app-firewall-policy-id {{WAF_POLICY_ID}} \\',
            '  --request-protection file://owasp-sqli-xss-rules.json',
            '',
            '# Step 2: Redeploy the application with parameterised queries / input sanitisation',
            '# (manual code fix required in application source - see {{VULN_ID}})',
        ]
    },
    "SESSION_MANAGEMENT|ORACLECLOUD": {
        "title": 'Remediate Oracle Cloud Session Management Weakness',
        "description": 'Shorten IDCS/IAM session token lifetime and revoke stale sessions.',
        "commands": [
            '# Step 1: Update the IDCS sign-on policy session duration',
            'oci identity-domains sign-on-policy update --sign-on-policy-id {{POLICY_ID}} \\',
            '  --max-session-duration 60',
            '',
            '# Step 2: Revoke active sessions for the affected user',
            'oci identity-domains user-session-delete --user-id {{USER_ID}}',
        ]
    },
    "DOMAIN_HIJACKING|ORACLECLOUD": {
        "title": 'Remediate Oracle Cloud Domain Hijacking Risk',
        "description": 'Remove dangling DNS records and lock the zone against unauthorized edits.',
        "commands": [
            '# Step 1: List record sets for dangling references',
            'oci dns record rrset get --zone-name-or-id {{ZONE_NAME}} --domain {{RECORD_NAME}} --rtype CNAME',
            '',
            '# Step 2: Delete the dangling record',
            'oci dns record rrset delete --zone-name-or-id {{ZONE_NAME}} --domain {{RECORD_NAME}} --rtype CNAME --force',
            '',
            '# Step 3: Apply a resource lock on the zone',
            'oci dns zone update --zone-name-or-id {{ZONE_NAME}} --freeform-tags \'{"Locked":"true"}\'',
        ]
    },
    "DATA_LOSS|ORACLECLOUD": {
        "title": 'Remediate Oracle Cloud Data Loss Risk',
        "description": 'Enable Object Storage versioning and configure a backup policy.',
        "commands": [
            '# Step 1: Enable versioning on the bucket',
            'oci os bucket update --bucket-name {{resource}} --versioning Enabled',
            '',
            '# Step 2: Attach a volume backup policy for block storage',
            'oci bv volume-backup-policy-assignment create \\',
            '  --asset-id {{VOLUME_OCID}} --policy-id {{BACKUP_POLICY_ID}}',
        ]
    },
    "ACCESS_CONTROL|IBMCLOUD": {
        "title": 'Remediate IBM Cloud Access Control Misconfiguration',
        "description": 'Replace the overly-broad IAM access policy with a least-privilege role.',
        "commands": [
            '# Step 1: List IAM policies for the service ID / user',
            'ibmcloud iam user-policies {{USER_EMAIL}}',
            '',
            '# Step 2: Remove the over-permissive policy',
            'ibmcloud iam user-policy-delete {{USER_EMAIL}} {{POLICY_ID}} --force',
            '',
            '# Step 3: Create a least-privilege replacement policy',
            'ibmcloud iam user-policy-create {{USER_EMAIL}} \\',
            '  --roles Viewer --service-name {{SERVICE_NAME}} --resource-group-name {{RESOURCE_GROUP}}',
        ]
    },
    "AUTHENTICATION|IBMCLOUD": {
        "title": 'Remediate IBM Cloud Authentication Weakness',
        "description": 'Rotate the exposed API key and enforce MFA on the account.',
        "commands": [
            '# Step 1: List API keys for the user',
            'ibmcloud iam api-keys',
            '',
            '# Step 2: Delete the exposed/default API key',
            'ibmcloud iam api-key-delete {{API_KEY_NAME}} --force',
            '',
            '# Step 3: Enforce MFA at the account level',
            'ibmcloud account mfa-update --type TOTP',
        ]
    },
    "PRIVILEGE_ESCALATION|IBMCLOUD": {
        "title": 'Remediate IBM Cloud Privilege Escalation Path',
        "description": 'Downgrade the over-privileged service ID role from Administrator to least-privilege.',
        "commands": [
            '# Step 1: List roles assigned to the service ID',
            'ibmcloud iam service-policies {{SERVICE_ID_NAME}}',
            '',
            '# Step 2: Remove the Administrator role assignment',
            'ibmcloud iam service-policy-delete {{SERVICE_ID_NAME}} {{POLICY_ID}} --force',
            '',
            '# Step 3: Assign a least-privilege Editor/Viewer role instead',
            'ibmcloud iam service-policy-create {{SERVICE_ID_NAME}} \\',
            '  --roles Editor --service-name {{SERVICE_NAME}}',
        ]
    },
    "DATA_EXPOSURE|IBMCLOUD": {
        "title": 'Remediate IBM Cloud Data Exposure',
        "description": 'Block public access on the Cloud Object Storage bucket and enable encryption.',
        "commands": [
            "# Step 1: Set the bucket's public access block",
            'ibmcloud cos bucket-update --bucket {{resource}} --public-access-block-enabled true',
            '',
            '# Step 2: Enable server-side encryption with a Key Protect root key',
            'ibmcloud cos bucket-update --bucket {{resource}} --kp-root-key-crn {{KP_ROOT_KEY_CRN}}',
            '',
            '# Step 3: Verify the bucket configuration',
            'ibmcloud cos bucket-get --bucket {{resource}}',
        ]
    },
    "NETWORK_SECURITY|IBMCLOUD": {
        "title": 'Remediate IBM Cloud Network Security Misconfiguration',
        "description": 'Restrict the security group rule allowing unrestricted inbound access.',
        "commands": [
            '# Step 1: List security group rules',
            'ibmcloud is security-group-rules {{resource}}',
            '',
            '# Step 2: Delete the unrestricted (0.0.0.0/0) inbound rule',
            'ibmcloud is security-group-rule-delete {{resource}} {{RULE_ID}} --force',
            '',
            '# Step 3: Add a restricted inbound rule from the trusted CIDR only',
            'ibmcloud is security-group-rule-add {{resource}} inbound tcp \\',
            '  --port-min 22 --port-max 22 --remote {{TRUSTED_CIDR}}',
        ]
    },
    "ENCRYPTION|IBMCLOUD": {
        "title": 'Remediate IBM Cloud Encryption Misconfiguration',
        "description": 'Enable automatic rotation on the Key Protect root key.',
        "commands": [
            '# Step 1: Check current key rotation policy',
            'ibmcloud kp key rotation-policy-get {{KEY_ID}} --instance-id {{KP_INSTANCE_ID}}',
            '',
            '# Step 2: Set the rotation interval to 12 months',
            'ibmcloud kp key rotation-policy-set {{KEY_ID}} --instance-id {{KP_INSTANCE_ID}} --interval 12',
        ]
    },
    "DATA_EXFILTRATION|IBMCLOUD": {
        "title": 'Remediate IBM Cloud Data Exfiltration Risk',
        "description": 'Restrict bucket read access and enable Activity Tracker for audit visibility.',
        "commands": [
            '# Step 1: Disable public/anonymous read access on the bucket',
            'ibmcloud cos bucket-update --bucket {{resource}} --public-access-block-enabled true',
            '',
            '# Step 2: Enable Activity Tracker event routing for the bucket',
            'ibmcloud atracker route-create --name track-{{resource}} \\',
            '  --targets {{TARGET_ID}} --rules file://route-rules.json',
        ]
    },
    "DENIAL_OF_SERVICE|IBMCLOUD": {
        "title": 'Remediate IBM Cloud Denial of Service Exposure',
        "description": 'Enable Cloud Internet Services (CIS) rate limiting and DDoS protection.',
        "commands": [
            '# Step 1: Create a rate-limiting rule on CIS',
            'ibmcloud cis rate-limit-create {{DOMAIN_ID}} \\',
            '  --threshold 100 --period 60 --action challenge',
            '',
            "# Step 2: Enable the 'Under Attack' / high security mode",
            'ibmcloud cis security-level-set {{DOMAIN_ID}} high',
        ]
    },
    "CODE_INJECTION|IBMCLOUD": {
        "title": 'Remediate IBM Cloud Code Injection Vulnerability',
        "description": 'Enable the CIS Web Application Firewall managed ruleset (OWASP core rules).',
        "commands": [
            '# Step 1: Enable the WAF for the domain',
            'ibmcloud cis waf-setting-update {{DOMAIN_ID}} --status on',
            '',
            '# Step 2: Enable the OWASP ModSecurity core ruleset package',
            'ibmcloud cis waf-package-update {{DOMAIN_ID}} {{OWASP_PACKAGE_ID}} \\',
            '  --sensitivity high --action-mode block',
        ]
    },
    "SESSION_MANAGEMENT|IBMCLOUD": {
        "title": 'Remediate IBM Cloud Session Management Weakness',
        "description": 'Shorten IAM access token lifetime and revoke stale sessions for the user.',
        "commands": [
            '# Step 1: Update the account session/token expiration policy',
            'ibmcloud account update-session-timeout --minutes 60',
            '',
            "# Step 2: Revoke the user's currently active sessions",
            'ibmcloud iam user-invite-revoke {{USER_EMAIL}}',
        ]
    },
    "DOMAIN_HIJACKING|IBMCLOUD": {
        "title": 'Remediate IBM Cloud Domain Hijacking Risk',
        "description": 'Remove dangling DNS records and lock the CIS zone against unauthorized changes.',
        "commands": [
            '# Step 1: List DNS records for the zone',
            'ibmcloud cis dns-records {{DOMAIN_ID}} --type CNAME',
            '',
            '# Step 2: Delete the dangling record',
            'ibmcloud cis dns-record-delete {{DOMAIN_ID}} {{RECORD_ID}}',
            '',
            '# Step 3: Lock the zone settings',
            'ibmcloud cis domain-lock-set {{DOMAIN_ID}} lock',
        ]
    },
    "DATA_LOSS|IBMCLOUD": {
        "title": 'Remediate IBM Cloud Data Loss Risk',
        "description": 'Enable Cloud Object Storage versioning and configure a backup vault.',
        "commands": [
            '# Step 1: Enable object versioning on the bucket',
            'ibmcloud cos bucket-update --bucket {{resource}} --versioning-enabled true',
            '',
            '# Step 2: Configure a Backup for VPC / COS backup policy',
            'ibmcloud backup-recovery protection-policy-create \\',
            '  --name {{BACKUP_POLICY_NAME}} --backup-frequency daily --retention-days 30',
        ]
    },
    "ACCESS_CONTROL|ALIBABACLOUD": {
        "title": 'Remediate Alibaba Cloud Access Control Misconfiguration',
        "description": 'Detach the overly-broad RAM policy and attach a least-privilege one.',
        "commands": [
            '# Step 1: List RAM policies attached to the user',
            'aliyun ram ListPoliciesForUser --UserName {{RAM_USER}}',
            '',
            '# Step 2: Detach the overly-permissive policy',
            'aliyun ram DetachPolicyFromUser --PolicyType Custom \\',
            '  --PolicyName {{POLICY_NAME}} --UserName {{RAM_USER}}',
            '',
            '# Step 3: Attach a least-privilege replacement policy',
            'aliyun ram AttachPolicyToUser --PolicyType Custom \\',
            '  --PolicyName {{LEAST_PRIV_POLICY}} --UserName {{RAM_USER}}',
        ]
    },
    "AUTHENTICATION|ALIBABACLOUD": {
        "title": 'Remediate Alibaba Cloud Authentication Weakness',
        "description": 'Disable the exposed AccessKey and enforce MFA for the RAM user.',
        "commands": [
            '# Step 1: List AccessKeys for the RAM user',
            'aliyun ram ListAccessKeys --UserName {{RAM_USER}}',
            '',
            '# Step 2: Disable the exposed AccessKey',
            'aliyun ram UpdateAccessKey --UserAccessKeyId {{ACCESS_KEY_ID}} \\',
            '  --UserName {{RAM_USER}} --Status Inactive',
            '',
            '# Step 3: Enforce MFA binding for the user',
            'aliyun ram BindMFADevice --UserName {{RAM_USER}} --SerialNumber {{MFA_SERIAL}}',
        ]
    },
    "PRIVILEGE_ESCALATION|ALIBABACLOUD": {
        "title": 'Remediate Alibaba Cloud Privilege Escalation Path',
        "description": 'Revoke the over-scoped RAM role trust policy / AdministratorAccess grant.',
        "commands": [
            "# Step 1: Show the role's current policy attachments",
            'aliyun ram ListPoliciesForRole --RoleName {{ROLE_NAME}}',
            '',
            '# Step 2: Detach AdministratorAccess from the role',
            'aliyun ram DetachPolicyFromRole --PolicyType System \\',
            '  --PolicyName AdministratorAccess --RoleName {{ROLE_NAME}}',
            '',
            '# Step 3: Attach a scoped, least-privilege policy instead',
            'aliyun ram AttachPolicyToRole --PolicyType Custom \\',
            '  --PolicyName {{LEAST_PRIV_POLICY}} --RoleName {{ROLE_NAME}}',
        ]
    },
    "DATA_EXPOSURE|ALIBABACLOUD": {
        "title": 'Remediate Alibaba Cloud Data Exposure',
        "description": 'Block public read on the OSS bucket and enable server-side encryption.',
        "commands": [
            '# Step 1: Set bucket ACL to private',
            'aliyun oss set-acl oss://{{resource}} private',
            '',
            '# Step 2: Enable server-side encryption (KMS)',
            'aliyun oss bucket-encryption --method put oss://{{resource}} \\',
            '  --sse-algorithm KMS --kms-key-id {{KMS_KEY_ID}}',
            '',
            '# Step 3: Verify the ACL is no longer public',
            'aliyun oss get-acl oss://{{resource}}',
        ]
    },
    "NETWORK_SECURITY|ALIBABACLOUD": {
        "title": 'Remediate Alibaba Cloud Network Security Misconfiguration',
        "description": 'Remove the unrestricted security group rule allowing 0.0.0.0/0 ingress.',
        "commands": [
            '# Step 1: List ingress rules on the security group',
            'aliyun ecs DescribeSecurityGroupAttribute --SecurityGroupId {{resource}}',
            '',
            '# Step 2: Revoke the unrestricted rule',
            'aliyun ecs RevokeSecurityGroup --SecurityGroupId {{resource}} \\',
            '  --IpProtocol tcp --PortRange 22/22 --SourceCidrIp 0.0.0.0/0',
            '',
            '# Step 3: Authorize access from the trusted CIDR only',
            'aliyun ecs AuthorizeSecurityGroup --SecurityGroupId {{resource}} \\',
            '  --IpProtocol tcp --PortRange 22/22 --SourceCidrIp {{TRUSTED_CIDR}}',
        ]
    },
    "ENCRYPTION|ALIBABACLOUD": {
        "title": 'Remediate Alibaba Cloud Encryption Misconfiguration',
        "description": 'Enable automatic rotation on the KMS customer master key.',
        "commands": [
            '# Step 1: Check current key rotation status',
            'aliyun kms DescribeKey --KeyId {{resource}}',
            '',
            '# Step 2: Enable automatic key rotation',
            'aliyun kms EnableKeyRotation --KeyId {{resource}} --RotationInterval 365d',
        ]
    },
    "DATA_EXFILTRATION|ALIBABACLOUD": {
        "title": 'Remediate Alibaba Cloud Data Exfiltration Risk',
        "description": 'Restrict OSS bucket read access and enable ActionTrail logging for audit visibility.',
        "commands": [
            '# Step 1: Disable public read on the bucket',
            'aliyun oss set-acl oss://{{resource}} private',
            '',
            '# Step 2: Enable ActionTrail to capture data-plane access events',
            'aliyun actiontrail CreateTrail --Name track-{{resource}} \\',
            '  --OssBucketName {{AUDIT_LOG_BUCKET}} --TrailRegion All',
        ]
    },
    "DENIAL_OF_SERVICE|ALIBABACLOUD": {
        "title": 'Remediate Alibaba Cloud Denial of Service Exposure',
        "description": 'Enable Anti-DDoS Basic thresholds and Auto Scaling on the affected instance group.',
        "commands": [
            '# Step 1: Configure Anti-DDoS Basic blackhole threshold',
            'aliyun ddosbasic ConfigureInstanceBlackhole --InstanceId {{INSTANCE_ID}} --Threshold 100',
            '',
            '# Step 2: Enable Auto Scaling for the scaling group',
            'aliyun ess ModifyScalingGroup --ScalingGroupId {{ASG_ID}} \\',
            '  --MinSize 2 --MaxSize 10',
        ]
    },
    "CODE_INJECTION|ALIBABACLOUD": {
        "title": 'Remediate Alibaba Cloud Code Injection Vulnerability',
        "description": 'Enable Web Application Firewall (WAF) protection rules for SQLi/XSS.',
        "commands": [
            '# Step 1: Enable the WAF protection ruleset for the domain',
            'aliyun waf-openapi ModifyDomain --InstanceId {{WAF_INSTANCE_ID}} \\',
            '  --Domain {{DOMAIN}} --ProtectionResourceType share',
            '',
            '# Step 2: Turn on the core rule set (CRS) group',
            'aliyun waf-openapi ModifyDefenseRuleStatus --InstanceId {{WAF_INSTANCE_ID}} \\',
            '  --Domain {{DOMAIN}} --DefenseType waf_group --RuleStatus 1',
        ]
    },
    "SESSION_MANAGEMENT|ALIBABACLOUD": {
        "title": 'Remediate Alibaba Cloud Session Management Weakness',
        "description": 'Shorten RAM STS token duration and revoke stale sessions.',
        "commands": [
            '# Step 1: Reduce the max session duration for the RAM role',
            'aliyun ram UpdateRole --RoleName {{ROLE_NAME}} --MaxSessionDuration 3600',
            '',
            "# Step 2: Revoke active sessions by rotating the role's trust policy",
            'aliyun ram UpdateRole --RoleName {{ROLE_NAME}} \\',
            '  --NewAssumeRolePolicyDocument file://trust-policy.json',
        ]
    },
    "DOMAIN_HIJACKING|ALIBABACLOUD": {
        "title": 'Remediate Alibaba Cloud Domain Hijacking Risk',
        "description": 'Remove dangling DNS records and lock the domain against unauthorized transfer.',
        "commands": [
            '# Step 1: List DNS records for the domain',
            'aliyun alidns DescribeDomainRecords --DomainName {{DOMAIN}} --TypeKeyWord CNAME',
            '',
            '# Step 2: Delete the dangling record',
            'aliyun alidns DeleteDomainRecord --RecordId {{RECORD_ID}}',
            '',
            '# Step 3: Enable domain transfer lock',
            'aliyun domain-intl SetDomainTransferOutProhibited --DomainName {{DOMAIN}}',
        ]
    },
    "DATA_LOSS|ALIBABACLOUD": {
        "title": 'Remediate Alibaba Cloud Data Loss Risk',
        "description": 'Enable OSS bucket versioning and configure a Hybrid Backup Recovery (HBR) plan.',
        "commands": [
            '# Step 1: Enable versioning on the bucket',
            'aliyun oss bucket-versioning --method put oss://{{resource}} --status Enabled',
            '',
            '# Step 2: Create a scheduled HBR backup plan',
            'aliyun hbr CreateBackupPlan --Name {{BACKUP_PLAN_NAME}} \\',
            "  --VaultId {{VAULT_ID}} --Schedule 'I|1602000000|P1D'",
        ]
    },

    # DEFAULT CREDENTIALS (keyword override, all providers)
    "DEFAULT_CREDENTIALS|AWS": {
        "title": 'Remediate AWS Default Credentials Exposure',
        "description": 'Rotate OS-level default credentials on the instance, revoke exposed cloud API keys, audit for unauthorized access, and restrict network exposure.',
        "commands": [
            '# Step 1: Force OS-level password reset via SSM (no SSH key needed)',
            'aws ssm send-command --instance-ids {{INSTANCE_ID}} \\',
            '  --document-name AWS-RunShellScript \\',
            '  --parameters \'commands=["passwd -e $(whoami)"]\'',
            '',
            '# Step 2: Rotate the EC2 key pair (replace the default/known key)',
            "aws ec2 create-key-pair --key-name {{NEW_KEY_NAME}} --query 'KeyMaterial' --output text",
            '',
            '# Step 3: Revoke any exposed IAM access keys tied to this instance role',
            'aws iam update-access-key --access-key-id {{ACCESS_KEY_ID}} --status Inactive --user-name {{IAM_USER}}',
            '',
            '# Step 4: Audit CloudTrail/OS auth logs for unauthorized access during exposure window',
            'aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue={{IAM_USER}}',
            '',
            '# Step 5: Restrict security group to essential ports only (remove 0.0.0.0/0 SSH/RDP)',
            'aws ec2 revoke-security-group-ingress --group-id {{SG_ID}} \\',
            '  --protocol tcp --port 22 --cidr 0.0.0.0/0',
        ]
    },
    "DEFAULT_CREDENTIALS|AZURE": {
        "title": 'Remediate Azure Default Credentials Exposure',
        "description": 'Rotate OS-level default credentials on the VM, revoke exposed service principal secrets, audit sign-in logs, and restrict NSG exposure.',
        "commands": [
            '# Step 1: Reset the local admin/OS password via Run Command',
            'az vm run-command invoke --resource-group {{RG_NAME}} --name {{VM_NAME}} \\',
            '  --command-id RunShellScript --scripts "echo \'{{USER}}:{{NEW_PASSWORD}}\' | chpasswd"',
            '',
            '# Step 2: Replace the default SSH public key on the VM',
            'az vm user update --resource-group {{RG_NAME}} --name {{VM_NAME}} \\',
            '  --username {{USER}} --ssh-key-value {{NEW_SSH_PUBLIC_KEY_PATH}}',
            '',
            '# Step 3: Revoke exposed service principal credentials',
            'az ad sp credential reset --id {{SP_APP_ID}} --append false',
            '',
            '# Step 4: Review Azure AD sign-in logs for unauthorized access',
            'az monitor activity-log list --resource-group {{RG_NAME}} --start-time {{WINDOW_START}}',
            '',
            '# Step 5: Restrict NSG to essential ports only',
            'az network nsg rule delete --resource-group {{RG_NAME}} --nsg-name {{NSG_NAME}} --name Allow-All-RDP',
        ]
    },
    "DEFAULT_CREDENTIALS|GCP": {
        "title": 'Remediate GCP Default Credentials Exposure',
        "description": 'Rotate OS-level default credentials on the instance, revoke exposed service account keys, audit access logs, and restrict firewall exposure.',
        "commands": [
            '# Step 1: Reset the OS login password via guest-attributes / OS Login reset',
            'gcloud compute reset-windows-password {{INSTANCE_NAME}} --zone {{ZONE}}',
            "# (Linux: gcloud compute ssh --command 'sudo passwd {{USER}}')",
            '',
            '# Step 2: Remove the default/compromised SSH key from project metadata',
            'gcloud compute instances remove-metadata {{INSTANCE_NAME}} --zone {{ZONE}} --keys=ssh-keys',
            '',
            '# Step 3: Delete the exposed service account key',
            'gcloud iam service-accounts keys delete {{KEY_ID}} --iam-account={{SA_EMAIL}}',
            '',
            '# Step 4: Review Cloud Audit Logs for unauthorized access',
            'gcloud logging read \'protoPayload.authenticationInfo.principalEmail="{{SA_EMAIL}}"\' --limit 50',
            '',
            '# Step 5: Restrict the firewall rule to essential ports only',
            'gcloud compute firewall-rules update {{FIREWALL_RULE}} --source-ranges={{TRUSTED_CIDR}}',
        ]
    },
    "DEFAULT_CREDENTIALS|ORACLECLOUD": {
        "title": 'Remediate Oracle Cloud Default Credentials Exposure',
        "description": 'Rotate OS-level default credentials on the compute instance, revoke exposed IAM API keys, audit access, and restrict security list exposure.',
        "commands": [
            '# Step 1: Reset the OS-level default password via Instance Console Connection',
            'oci compute instance-console-connection create --instance-id {{INSTANCE_OCID}} \\',
            '  --public-key-file {{CONSOLE_SSH_KEY_PATH}}',
            '# then connect and run: passwd {{USER}}',
            '',
            '# Step 2: Replace the default SSH key via cloud-init/instance metadata update',
            'oci compute instance update --instance-id {{INSTANCE_OCID}} \\',
            '  --metadata \'{"ssh_authorized_keys":"{{NEW_SSH_PUBLIC_KEY}}"}\'',
            '',
            '# Step 3: Delete the exposed/default IAM API signing key',
            'oci iam user api-key delete --user-id {{USER_ID}} --fingerprint {{KEY_FINGERPRINT}} --force',
            '',
            '# Step 4: Enforce MFA on the IAM user account',
            'oci iam mfa-totp-device create --user-id {{USER_ID}}',
            '',
            '# Step 5: Audit Cloud Guard / Audit service logs for unauthorized access',
            'oci audit event list --compartment-id {{COMPARTMENT_ID}} --start-time {{WINDOW_START}}',
            '',
            '# Step 6: Restrict the security list to essential ports only',
            'oci network security-list update --security-list-id {{resource}} \\',
            '  --ingress-security-rules file://restricted-ingress-rules.json',
        ]
    },
    "DEFAULT_CREDENTIALS|IBMCLOUD": {
        "title": 'Remediate IBM Cloud Default Credentials Exposure',
        "description": 'Rotate OS-level default credentials on the VSI, revoke exposed API keys, audit Activity Tracker events, and restrict security group exposure.',
        "commands": [
            '# Step 1: Reset the OS-level default password/SSH key on the VSI',
            'ibmcloud is instance-initialization {{INSTANCE_ID}} --key-ids {{NEW_SSH_KEY_ID}} --user-data-file reset-creds.sh',
            '',
            '# Step 2: Delete the exposed/default API key',
            'ibmcloud iam api-key-delete {{API_KEY_NAME}} --force',
            '',
            '# Step 3: Enforce MFA at the account level',
            'ibmcloud account mfa-update --type TOTP',
            '',
            '# Step 4: Review Activity Tracker events for unauthorized access',
            'ibmcloud atracker events --start-time {{WINDOW_START}}',
            '',
            '# Step 5: Restrict the security group to essential ports only',
            'ibmcloud is security-group-rule-delete {{resource}} {{RULE_ID}} --force',
        ]
    },
    "DEFAULT_CREDENTIALS|ALIBABACLOUD": {
        "title": 'Remediate Alibaba Cloud Default Credentials Exposure',
        "description": 'Rotate OS-level default credentials on the ECS instance, revoke exposed AccessKeys, audit logs, and restrict security group exposure.',
        "commands": [
            '# Step 1: Reset the OS-level default password on the ECS instance',
            'aliyun ecs SetInstancePassword --InstanceId {{INSTANCE_ID}} --Password {{NEW_PASSWORD}}',
            '',
            '# Step 2: Replace the default SSH key pair binding',
            'aliyun ecs DetachKeyPair --KeyPairName {{OLD_KEY_NAME}} --InstanceIds \'["{{INSTANCE_ID}}"]\'',
            'aliyun ecs AttachKeyPair --KeyPairName {{NEW_KEY_NAME}} --InstanceIds \'["{{INSTANCE_ID}}"]\'',
            '',
            '# Step 3: Disable the exposed/default AccessKey',
            'aliyun ram UpdateAccessKey --UserAccessKeyId {{ACCESS_KEY_ID}} --UserName {{RAM_USER}} --Status Inactive',
            '',
            '# Step 4: Review ActionTrail for unauthorized access during exposure window',
            'aliyun actiontrail LookupEvents --StartTime {{WINDOW_START}}',
            '',
            '# Step 5: Restrict the security group to essential ports only',
            'aliyun ecs RevokeSecurityGroup --SecurityGroupId {{resource}} \\',
            '  --IpProtocol tcp --PortRange 22/22 --SourceCidrIp 0.0.0.0/0',
        ]
    },
}
