# -*- coding: utf-8 -*-
"""Dataset ingestion and cleaning.

Loads the cloud vulnerabilities dataset, normalises its columns, drops
unusable and out-of-scope records, and flags data-quality issues for review
rather than discarding them.

The dataset is read from a local JSONL file bundled with the project
(data/cloud_vulnerabilities_dataset.jsonl) rather than fetched from
HuggingFace at runtime. This keeps the pipeline deterministic and usable
without network access, and matches exactly the data this system's
remediation template library and verified signatures were curated against.
"""

import json
import re
from pathlib import Path

import pandas as pd

DEFAULT_DATASET_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "cloud_vulnerabilities_dataset.jsonl"
)

REQUIRED_COLUMNS = ["id", "description", "category", "cloud_provider"]
MIN_DESCRIPTION_LENGTH = 10

# Severity mapping, derived from category since the dataset has no severity
# field. Fallback only - cvss_scorer.score_dataframe() is the real source of
# severity once scoring runs; this gives the Step-0 preview a usable value.
CATEGORY_SEVERITY = {
    "Privilege Escalation": "CRITICAL",
    "Code Injection":       "CRITICAL",
    "Authentication":       "CRITICAL",
    "Access Control":       "HIGH",
    "Data Exfiltration":    "HIGH",
    "Network Security":     "HIGH",
    "Data Exposure":        "HIGH",
    "Encryption":           "MEDIUM",
    "Session Management":   "MEDIUM",
    "Denial of Service":    "MEDIUM",
    "Domain Hijacking":     "MEDIUM",
    "Data Loss":            "LOW",
}
KNOWN_CATEGORIES = set(CATEGORY_SEVERITY.keys())
KNOWN_PROVIDERS = {"AWS", "Azure", "GCP", "OracleCloud", "IBMCloud", "AlibabaCloud"}

# Providers with reviewed templates and verified signatures. Records for any
# other provider are dropped during cleaning. KNOWN_PROVIDERS stays wider so
# an out-of-scope provider is reported as a scope drop rather than an
# unrecognised label.
SUPPORTED_PROVIDERS = ("AWS", "Azure", "GCP")


def _filter_supported_providers(df: pd.DataFrame) -> pd.DataFrame:
    """
    Restrict a freshly-loaded frame to AWS / Azure / GCP records only, using
    the same canonicalisation as the cleaning-stage scope filter. Applied at
    LOAD time (not just during cleaning) so a caller who asks for `limit`
    records gets up to `limit` in-scope records, instead of `limit` being
    spent on rows for unsupported providers that clean_dataframe() would
    have dropped anyway.
    """
    if df.empty or "cloud_provider" not in df.columns:
        return df
    in_scope = df["cloud_provider"].map(_canonical_provider).isin(SUPPORTED_PROVIDERS)
    return df[in_scope].reset_index(drop=True)


# Step 1: Fetch from HuggingFace (the only supported source)
def _apply_limit(df, limit):
    """Return the first `limit` rows, or every row when limit is None."""
    return df if limit is None else df.head(limit)


def load_from_huggingface(limit: int = None):
    """
    STEP 1 - Retrieve raw data from HuggingFace Cloud Vulnerabilities Dataset.
    Tries:
      1. HuggingFace datasets library (pip install datasets)
      2. HuggingFace REST API  (pip install requests)
      3. Built-in offline mirror sample (used only when neither is reachable)

    All three paths return the SAME dataset - this is not a "pick a source"
    menu, just fallbacks for connectivity. Returns: (df, source_label)

    Scope is restricted to SUPPORTED_PROVIDERS (AWS / Azure / GCP) here, at
    load time, not left to the cleaning stage - so `limit` counts in-scope
    records rather than being partly spent on providers this system doesn't
    support and would drop anyway.

    `limit=None` (the default) returns every in-scope record. Pass an integer
    only when a smaller sample is wanted.
    """

    # Method 1: datasets library. The full split is filtered to scope
    # BEFORE `limit` is applied, since it's already in memory.
    try:
        from datasets import load_dataset
        ds = load_dataset(
            "darkknight25/Cloud_Vulnerabilities_Dataset",
            split="train",
            trust_remote_code=True,
        )
        df = ds.to_pandas()
        df = _normalise(df)
        df = _filter_supported_providers(df)
        return _apply_limit(df, limit), "HuggingFace Datasets Library (live - {} in-scope records)".format(len(df))
    except Exception:
        pass

    # Method 2: REST API. This endpoint only supports offset/limit, not a
    # provider filter, so a plain `limit`-sized page could come back mostly
    # out-of-scope. Over-fetch a larger page, filter to scope, then take
    # `limit` - so the returned records are still in-scope-only.
    try:
        import requests
        fetch_n = 1000 if limit is None else min(max(limit * 5, limit), 1000)
        url = (
            "https://datasets-server.huggingface.co/rows"
            "?dataset=darkknight25%2FCloud_Vulnerabilities_Dataset"
            "&config=default&split=train&offset=0&limit={}".format(fetch_n)
        )
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        rows = resp.json().get("rows", [])
        if rows:
            records = [r["row"] for r in rows]
            df = pd.DataFrame(records)
            df = _normalise(df)
            df = _filter_supported_providers(df)
            df = _apply_limit(df, limit)
            return df, "HuggingFace REST API (live - {} in-scope records)".format(len(df))
    except Exception:
        pass

    # Method 3: Offline mirror fallback (still the HuggingFace dataset content,
    # just a local copy for when neither network path above is reachable)
    df = pd.DataFrame(_OFFLINE_SAMPLE)
    df = _normalise(df)
    df = _filter_supported_providers(df)
    return df, "HuggingFace Dataset - Offline Mirror (no internet - {} in-scope records)".format(len(df))


def load_from_local_jsonl(path=None, limit: int = None):
    """
    Retrieve raw data from a local JSONL file instead of HuggingFace.

    Same contract as load_from_huggingface(): scope is restricted to
    SUPPORTED_PROVIDERS at load time (before `limit` is applied), so `limit`
    counts in-scope records rather than being partly spent on rows this
    system doesn't support and would drop anyway.

    `limit=None` (the default) returns every in-scope record.
    Returns: (df, source_label)
    """
    path = Path(path) if path else DEFAULT_DATASET_PATH

    if not path.exists():
        raise FileNotFoundError(
            "Dataset file not found at {}. Place the JSONL dataset there, "
            "or pass an explicit path to load_from_local_jsonl().".format(path)
        )

    records = []
    with open(path, "r", encoding="utf-8") as fh:
        for line_num, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                import warnings
                warnings.warn(
                    "Skipping malformed JSON on line {} of {}: {}".format(
                        line_num, path, e),
                    RuntimeWarning,
                )

    df = pd.DataFrame(records)
    df = _normalise(df)
    df = _filter_supported_providers(df)
    return _apply_limit(df, limit), "Local Dataset File - {} ({} in-scope records)".format(
        path.name, len(df))


def load_and_clean_from_local_jsonl(path=None, limit: int = None) -> tuple:
    """
    THE single supported entry point for loading data into the pipeline.
    Reads the local JSONL dataset, then runs the full cleaning pass, and
    always returns:
        (clean_df, source_label, cleaning_report)
    so nothing downstream can accidentally see un-cleaned data, and a human
    always has the report to review before Step 2 (CVSS scoring).
    """
    df_raw, label = load_from_local_jsonl(path=path, limit=limit)
    df_clean, report = clean_dataframe(df_raw)
    return df_clean, label, report


# Provider-mismatch detection.
#
# Some records carry a cloud_provider label that disagrees with the provider
# named in the description. The mapping engine trusts the structured column,
# so a mislabelled row would generate a script for the wrong provider.
# These rows are flagged for the review step instead.
_PROVIDER_NAME_PATTERNS = {
    "AWS":           [r"\bamazon\s+web\s+services\b", r"\baws\b"],
    "Azure":         [r"\bmicrosoft\s+azure\b", r"\bazure\b"],
    "GCP":           [r"\bgoogle\s+cloud\b", r"\bgcp\b"],
    "OracleCloud":   [r"\boracle\s+cloud\b", r"\boci\b"],
    "IBMCloud":      [r"\bibm\s+cloud\b"],
    "AlibabaCloud":  [r"\balibaba\s+cloud\b", r"\baliyun\b"],
}


def _canonical_provider(value: str) -> str:
    v = str(value).strip().upper()
    if "AWS" in v or "AMAZON" in v:
        return "AWS"
    if "AZURE" in v or "MICROSOFT" in v:
        return "Azure"
    if "GCP" in v or "GOOGLE" in v:
        return "GCP"
    if "ORACLE" in v or v == "OCI":
        return "OracleCloud"
    if "IBM" in v:
        return "IBMCloud"
    if "ALIBABA" in v or "ALIYUN" in v:
        return "AlibabaCloud"
    return v.title().replace(" ", "") if v and v != "UNKNOWN" else "Unknown"


def _mentioned_providers(description: str) -> list:
    text = str(description).lower()
    found = []
    for provider, patterns in _PROVIDER_NAME_PATTERNS.items():
        if any(re.search(p, text) for p in patterns):
            found.append(provider)
    return found


def flag_provider_mismatches(df: pd.DataFrame) -> pd.DataFrame:
    """
    Adds `provider_conflict` (bool) and `provider_conflict_note` (str)
    columns. A conflict means the description names a DIFFERENT cloud
    provider than the structured cloud_provider column - a data-quality
    issue worth a human's attention before a script is approved.
    """
    df = df.copy()
    labeled = df["cloud_provider"].map(_canonical_provider)
    mentioned = df["description"].map(_mentioned_providers)

    conflicts, notes = [], []
    for label, mention_list in zip(labeled, mentioned):
        other_mentions = [p for p in mention_list if p != label]
        if other_mentions:
            conflicts.append(True)
            notes.append(
                "Labeled '{}' but description names '{}' - verify before approving."
                .format(label, "', '".join(other_mentions))
            )
        else:
            conflicts.append(False)
            notes.append("")

    df["provider_conflict"] = conflicts
    df["provider_conflict_note"] = notes
    return df


# Confirmed-invalid vulnerable_code snippets.
#
# Curated list of vulnerable_code CLI snippets confirmed invalid during
# review. Not a general syntax validator - extend as new cases are found.
_CONFIRMED_BAD_CLI_SNIPPETS = [
    {
        "pattern": re.compile(r"\baks\s+create\b.*--enable-admin\b", re.IGNORECASE),
        "note": ("'az aks create ... --enable-admin' is not valid Azure CLI syntax - "
                 "there is no --enable-admin flag. AKS local admin accounts are enabled "
                 "by DEFAULT (no flag needed); the real fix is --disable-local-accounts, "
                 "which the generated remediation script already applies. Treat this "
                 "vulnerable_code sample as illustrative, not a literal reproduction step."),
    },
]

# Recognisable CLI prefixes, used only to decide whether a vulnerable_code
# value looks like a command at all (informational - not itself a flag).
_CLI_PREFIXES = ("aws ", "az ", "gcloud ", "oci ", "ibmcloud ", "aliyun ")

# Executable-code check.
#
# `vulnerable_code` should show the misconfiguration as code: a CLI call or
# key/value config syntax (Effect: Allow, cidr_ip: ..., etc). Some rows
# instead carry plain prose with no code structure, which is unusable
# downstream. This is a general structural check (CLI prefixes, flags,
# key/value or bracket syntax) - not a per-snippet validator - and runs
# before the curated _CONFIRMED_BAD_CLI_SNIPPETS check above, which catches
# specific known-bad commands rather than "not code at all".
_CODE_STRUCTURE_PATTERN = re.compile(
    r"--[a-zA-Z]"       # a CLI flag, e.g. --no-assign-ip
    r"|[A-Za-z_][A-Za-z0-9_]*\s*[:=]\s*\S"   # key: value / key=value
    r"|\{\{|\{[\"']|\[[\"'0-9]"              # {{PLACEHOLDER}}, JSON-ish
    r"|^\s*[\[{]"                            # starts with [ or {
    r"|://"                                  # gs://, oss://, https://
)


def is_executable_code(text: str) -> bool:
    """
    True when `text` has code-like structure (CLI invocation or key/value
    config syntax). False for empty values and for plain prose sentences
    that carry no code structure at all.
    """
    text = str(text).strip()
    if not text:
        return False
    lower = text.lower()
    if any(lower.startswith(p) for p in _CLI_PREFIXES):
        return True
    return bool(_CODE_STRUCTURE_PATTERN.search(text))


def flag_bad_cli_examples(df: pd.DataFrame) -> pd.DataFrame:
    """
    Adds `cli_example_flag` (bool) and `cli_example_flag_note` (str).
    Flags only snippets matching a confirmed-invalid pattern above. Flagging
    every CLI snippet as unverified would mark nearly every record and bury
    the signal.
    """
    df = df.copy()
    if "vulnerable_code" not in df.columns:
        df["cli_example_flag"] = False
        df["cli_example_flag_note"] = ""
        return df

    flags, notes = [], []
    for code in df["vulnerable_code"]:
        text = str(code)
        matched_note = ""
        for rule in _CONFIRMED_BAD_CLI_SNIPPETS:
            if rule["pattern"].search(text):
                matched_note = rule["note"]
                break
        flags.append(bool(matched_note))
        notes.append(matched_note)

    df["cli_example_flag"] = flags
    df["cli_example_flag_note"] = notes
    return df


# Internal helpers
def _normalise(df: pd.DataFrame) -> pd.DataFrame:
    """Standardise columns to match the real dataset schema."""
    df.columns = [c.lower().strip() for c in df.columns]

    rename_map = {
        "cloud provider":    "cloud_provider",
        "cloudprovider":     "cloud_provider",
        "provider":          "cloud_provider",
        "vuln_id":           "id",
        "vulnerability_id":  "id",
        "type":              "category",
        "vulnerability":     "category",
        "severity":          "severity_raw",
    }
    df = df.rename(columns=rename_map)

    for col in REQUIRED_COLUMNS:
        if col not in df.columns:
            df[col] = "UNKNOWN"
    if "vulnerable_code" not in df.columns:
        df["vulnerable_code"] = ""

    df["severity"] = df["category"].map(CATEGORY_SEVERITY).fillna("MEDIUM")
    df["service"] = df.apply(_infer_service, axis=1)

    df["cloud_provider"] = df["cloud_provider"].astype(str).str.strip()
    df["cloud_provider"] = df["cloud_provider"].replace({
        "Amazon Web Services": "AWS",
        "Microsoft Azure":     "Azure",
        "Google Cloud":        "GCP",
        "Google Cloud Platform": "GCP",
    })

    # Deduplication and short-description dropping happen once, in
    # clean_dataframe() below - not here - so the cleaning report's counts
    # stay accurate.
    df = df.dropna(subset=["id", "description"])
    df = df.reset_index(drop=True)

    df = flag_provider_mismatches(df)
    df = flag_bad_cli_examples(df)

    return df


def _infer_service(row) -> str:
    """Derive a short service tag from description and category."""
    text = (str(row.get("description", "")) + " " + str(row.get("category", ""))).lower()

    # Specific resource/service keywords are checked before the generic
    # "policy"/"role"/"key" catch-alls, since those words also show up in
    # descriptions of other services ("S3 bucket policy", "NSG policy",
    # "SSH key") and would otherwise mis-tag those records as IAM/Encryption.
    if "s3" in text or "bucket" in text or "blob" in text or "storage" in text:
        return "Storage"
    if "rds" in text or "database" in text or "sql" in text:
        return "Database"
    if "ec2" in text or "instance" in text or "vm " in text:
        return "Compute"
    if "lambda" in text or "function" in text or "serverless" in text:
        return "Serverless"
    if "vpc" in text or "network" in text or "firewall" in text or "nsg" in text or "security group" in text:
        return "Network"
    if "cloudtrail" in text or "logging" in text or "audit" in text or "monitor" in text:
        return "Logging"
    if "container" in text or "docker" in text or "kubernetes" in text or "k8s" in text:
        return "Container"
    if "api" in text or "gateway" in text:
        return "API"
    if "kms" in text or "encrypt" in text:
        return "Encryption"
    if ("access key" in text or "api key" in text or "ssh key" in text
            or "secret" in text or "credential" in text
            or "password" in text or "token" in text):
        return "Secrets"
    if "injection" in text or "xss" in text or "sqli" in text:
        return "AppSec"
    if "session" in text:
        return "Session"
    # Generic IAM/RBAC catch-all - checked LAST, only after nothing more
    # specific matched, since "role"/"policy"/"iam" alone are too broad
    # to be trusted as the first signal.
    if ("iam" in text or "role" in text or "policy" in text
            or "access control" in text or "privilege" in text
            or "permission" in text):
        return "IAM"
    return "General"


# Step 1.3: Cleaning pipeline - runs automatically before anything
# downstream sees the data. Returns (clean_df, report) so drop/flag counts
# are always visible.
def clean_dataframe(df: pd.DataFrame) -> tuple:
    """
    Applies, in order:
      1. Whitespace scrub on all text columns
      2. Drop rows with a missing/too-short description
      2b. DROP rows whose vulnerable_code is present but not executable
          code (prose with no CLI/config structure) - see
          is_executable_code() above.
      3. Drop duplicate ids (keep first)
      3b. DROP rows with a confirmed-invalid vulnerable_code CLI snippet
          (see _CONFIRMED_BAD_CLI_SNIPPETS above).
      3c. DROP rows whose provider is outside SUPPORTED_PROVIDERS
          (AWS / Azure / GCP). See the SUPPORTED_PROVIDERS note above.
      4. Flag (not drop) unknown category values
      5. Flag (not drop) unknown/unresolvable cloud_provider values
      6. Flag description/cloud_provider mismatches (already computed in
         _normalise, carried through)

    Unknown category and provider values are flagged rather than dropped, so
    a mislabelled but real finding still reaches a fallback template.
    Everything else dropped above (missing description, non-executable
    vulnerable_code, duplicate id, confirmed-invalid CLI snippet,
    out-of-scope provider) is unreviewable or out of this system's scope,
    so it's removed rather than passed downstream.
    """
    raw_count = len(df)
    reasons = []

    df = df.copy()
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].astype(str).str.strip()

    before = len(df)
    df = df[df["description"].str.len() >= MIN_DESCRIPTION_LENGTH]
    dropped_short_desc = before - len(df)

    # Drop rows whose vulnerable_code is present but not executable code
    # (plain prose with no CLI/config structure), so nothing downstream
    # sees a non-code sample. Rows with an EMPTY vulnerable_code are kept -
    # that's a missing value, not bad data, and the mapping engine doesn't
    # need it to attach a template.
    before = len(df)
    has_code = df["vulnerable_code"].astype(str).str.strip().eq("")
    non_executable_mask = (~has_code) & (~df["vulnerable_code"].map(is_executable_code))
    dropped_non_executable_ids = df.loc[non_executable_mask, "id"].tolist()
    df = df[~non_executable_mask]
    dropped_non_executable_code = before - len(df)

    before = len(df)
    df = df.drop_duplicates(subset=["id"])
    dropped_duplicates = before - len(df)

    # Drop rows with a confirmed-invalid vulnerable_code CLI snippet
    # (matches the curated _CONFIRMED_BAD_CLI_SNIPPETS list above). These
    # records aren't reviewable, so they're dropped rather than flagged.
    if "cli_example_flag" not in df.columns:
        df = flag_bad_cli_examples(df)
    before = len(df)
    bad_cli_mask = df["cli_example_flag"]
    dropped_confirmed_bad_cli_ids = df.loc[bad_cli_mask, "id"].tolist()
    df = df[~bad_cli_mask].drop(columns=["cli_example_flag", "cli_example_flag_note"])
    dropped_confirmed_bad_cli = before - len(df)

    # Scope filter. Filtering on the structured label rather than the
    # description keeps free text from overriding a labelled field. Dropped
    # rows whose description names a supported provider are listed by id in
    # the report, since those are potential mislabels worth reviewing.
    df["_canonical_provider"] = df["cloud_provider"].map(_canonical_provider)
    in_scope = df["_canonical_provider"].isin(SUPPORTED_PROVIDERS)

    dropped_rows = df[~in_scope]
    dropped_breakdown = (dropped_rows["_canonical_provider"]
                         .value_counts().to_dict())

    salvageable = []
    for _, r in dropped_rows.iterrows():
        mentioned = [p for p in _mentioned_providers(r["description"])
                     if p in SUPPORTED_PROVIDERS]
        if mentioned:
            salvageable.append({
                "id":               r["id"],
                "labelled":         r["_canonical_provider"],
                "description_says": ", ".join(mentioned),
            })

    df = df[in_scope].drop(columns=["_canonical_provider"]).reset_index(drop=True)
    dropped_out_of_scope = len(dropped_rows)

    unknown_category_mask = ~df["category"].isin(KNOWN_CATEGORIES)
    unknown_provider_mask = ~df["cloud_provider"].map(_canonical_provider).isin(KNOWN_PROVIDERS)
    df["unknown_category_flag"] = unknown_category_mask
    df["unknown_provider_flag"] = unknown_provider_mask

    if "provider_conflict" not in df.columns:
        df = flag_provider_mismatches(df)

    report = {
        "raw_records":              raw_count,
        "clean_records":            len(df),
        "dropped_short_description": dropped_short_desc,
        "dropped_non_executable_code": dropped_non_executable_code,
        "dropped_non_executable_code_ids": dropped_non_executable_ids,
        "dropped_duplicate_ids":    dropped_duplicates,
        "dropped_confirmed_bad_cli_example": dropped_confirmed_bad_cli,
        "dropped_confirmed_bad_cli_example_ids": dropped_confirmed_bad_cli_ids,
        "supported_providers":      list(SUPPORTED_PROVIDERS),
        "dropped_out_of_scope":     dropped_out_of_scope,
        "dropped_by_provider":      dropped_breakdown,
        "dropped_but_description_names_supported": salvageable,
        "flagged_unknown_category": int(unknown_category_mask.sum()),
        "flagged_unknown_provider": int(unknown_provider_mask.sum()),
        "flagged_provider_conflict": int(df["provider_conflict"].sum()) if "provider_conflict" in df else 0,
    }
    return df, report


def load_and_clean_from_huggingface(limit: int = None) -> tuple:
    """
    THE single supported entry point for loading data into the pipeline.
    Fetches from HuggingFace (or its offline mirror), then runs the full
    cleaning pass, and always returns:
        (clean_df, source_label, cleaning_report)
    so nothing downstream can accidentally see un-cleaned data, and a
    human always has the report to review before Step 2 (CVSS scoring).
    """
    df_raw, label = load_from_huggingface(limit=limit)
    df_clean, report = clean_dataframe(df_raw)
    return df_clean, label, report


def get_provider_conflicts(df: pd.DataFrame) -> pd.DataFrame:
    """Return only the rows flagged with a provider/description conflict."""
    if "provider_conflict" not in df.columns:
        df = flag_provider_mismatches(df)
    return df[df["provider_conflict"]].copy()


def get_flagged_records(df: pd.DataFrame) -> pd.DataFrame:
    """Return every row carrying ANY data-quality flag, for one-stop HITL review.

    Note: confirmed-invalid CLI snippets and non-executable vulnerable_code
    are dropped during cleaning rather than flagged, so cli_example_flag
    no longer appears on a cleaned frame - it's kept in flag_cols only so
    this still works on an un-cleaned/raw frame if ever called on one.
    """
    flag_cols = [c for c in ("unknown_category_flag", "unknown_provider_flag",
                              "provider_conflict", "cli_example_flag") if c in df.columns]
    if not flag_cols:
        return df.iloc[0:0]
    mask = df[flag_cols].any(axis=1)
    return df[mask].copy()


# Offline mirror, used only when neither the `datasets` library nor the
# HuggingFace REST API is reachable.
_OFFLINE_SAMPLE = [
    {"id": "VUL0001", "description": "IAM role with wildcard (*) permissions on all AWS resources allowing unrestricted access", "category": "Access Control", "cloud_provider": "AWS", "vulnerable_code": "Effect: Allow, Action: '*', Resource: '*'"},
    {"id": "VUL0002", "description": "S3 bucket configured with public read access exposing sensitive customer data", "category": "Data Exposure", "cloud_provider": "AWS", "vulnerable_code": "BlockPublicAcls: false"},
    {"id": "VUL0003", "description": "Root account access keys actively used in production environment without MFA", "category": "Authentication", "cloud_provider": "AWS", "vulnerable_code": "aws_access_key_id = AKIA..."},
    {"id": "VUL0004", "description": "EC2 security group allows unrestricted SSH access from 0.0.0.0/0", "category": "Network Security", "cloud_provider": "AWS", "vulnerable_code": "cidr_ip: 0.0.0.0/0, port: 22"},
    {"id": "VUL0005", "description": "RDS instance is publicly accessible and uses default admin credentials", "category": "Authentication", "cloud_provider": "AWS", "vulnerable_code": "publicly_accessible: true"},
    {"id": "VUL0006", "description": "CloudTrail logging disabled across all regions leaving no audit trail", "category": "Data Exposure", "cloud_provider": "AWS", "vulnerable_code": "IsLogging: false"},
    {"id": "VUL0007", "description": "Azure Blob Storage container allows anonymous public access to sensitive files", "category": "Data Exposure", "cloud_provider": "Azure", "vulnerable_code": "PublicAccess: Container"},
    {"id": "VUL0008", "description": "Service principal assigned Owner role at subscription scope violating least privilege", "category": "Privilege Escalation", "cloud_provider": "Azure", "vulnerable_code": "roleDefinitionId: Owner"},
    {"id": "VUL0009", "description": "Azure Key Vault soft delete disabled allowing permanent deletion of encryption keys", "category": "Encryption", "cloud_provider": "Azure", "vulnerable_code": "enableSoftDelete: false"},
    {"id": "VUL0010", "description": "NSG rule allows all inbound traffic on RDP port 3389 from any internet source", "category": "Network Security", "cloud_provider": "Azure", "vulnerable_code": "sourceAddressPrefix: *, destinationPortRange: 3389"},
    {"id": "VUL0011", "description": "GCP service account has editor role at project level enabling excessive permissions", "category": "Privilege Escalation", "cloud_provider": "GCP", "vulnerable_code": "role: roles/editor"},
    {"id": "VUL0012", "description": "GCP Cloud Storage bucket is publicly accessible without authentication required", "category": "Data Exposure", "cloud_provider": "GCP", "vulnerable_code": "allUsers: READER"},
    {"id": "VUL0013", "description": "KMS customer-managed key rotation disabled for over 365 days increasing compromise risk", "category": "Encryption", "cloud_provider": "AWS", "vulnerable_code": "EnableKeyRotation: false"},
    {"id": "VUL0014", "description": "Lambda function environment variables contain plaintext API keys and database passwords", "category": "Data Exposure", "cloud_provider": "AWS", "vulnerable_code": "DB_PASSWORD=plaintext123"},
    {"id": "VUL0015", "description": "Azure AD conditional access policies not enforced allowing access without MFA", "category": "Authentication", "cloud_provider": "Azure", "vulnerable_code": "requireMfa: false"},
]
