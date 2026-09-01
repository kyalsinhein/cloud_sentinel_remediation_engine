# -*- coding: utf-8 -*-
"""CVSS v4.0 risk scoring.

Scores are computed by the `cvss` package's CVSS4 implementation, which
encodes the official FIRST.org macrovector and equivalence-class tables.

The dataset supplies no CVSS vector, so a Base metric vector is derived
deterministically from each record's category using the mapping in
CATEGORY_VECTORS below. Severity is then taken from the computed score using
the FIRST.org rating bands, rather than being assigned independently.

Specification: https://www.first.org/cvss/v4.0/specification-document
"""

import pandas as pd
from cvss import CVSS4
from cvss.exceptions import CVSS4MandatoryError

# ---------------------------------------------------------------------------
# Base metric vector per dataset category.
#
# Metric definitions (CVSS v4.0 Base metrics):
#   AV  Attack Vector           N=Network A=Adjacent L=Local P=Physical
#   AC  Attack Complexity       L=Low H=High
#   AT  Attack Requirements     N=None P=Present
#   PR  Privileges Required     N=None L=Low H=High
#   UI  User Interaction        N=None P=Passive A=Active
#   VC/VI/VA  Impact to the Vulnerable System (Confidentiality/Integrity/Availability)
#   SC/SI/SA  Impact to Subsequent Systems (blast radius beyond the vulnerable system)
#
# Rationale (short form):
#   - Privilege Escalation / Code Injection: remotely exploitable without
#     prior privileges, full compromise, with impact on subsequent systems.
#   - Authentication weaknesses (e.g. exposed root keys, no MFA): remote,
#     no privileges/interaction needed, breaks confidentiality+integrity
#     of the account itself.
#   - Access Control (over-broad IAM/policies): remote, no interaction,
#     mainly a confidentiality/integrity exposure of the resource.
#   - Data Exposure / Data Exfiltration: remote read-path exposure,
#     confidentiality-dominant impact.
#   - Network Security (open ports/firewalls): remote, but only "Present"
#     attack requirements (the attacker still needs to find/reach the
#     exposed service) and partial (Low) impact per CIA leg.
#   - Encryption gaps: require an additional attack step (AT:P), such as
#     first obtaining access to the stored ciphertext.
#   - Session Management: usually needs some user/session interaction.
#   - Denial of Service: availability-only impact.
#   - Domain Hijacking: integrity-dominant (traffic/DNS redirection).
#   - Data Loss: integrity and availability of the data itself; a retention
#     or backup gap rather than an interactive attack.
# ---------------------------------------------------------------------------
CATEGORY_VECTORS = {
    "Privilege Escalation": dict(AV="N", AC="L", AT="N", PR="L", UI="N",
                                  VC="H", VI="H", VA="H", SC="H", SI="H", SA="H"),
    "Code Injection":       dict(AV="N", AC="L", AT="N", PR="N", UI="N",
                                  VC="H", VI="H", VA="H", SC="L", SI="L", SA="N"),
    "Authentication":       dict(AV="N", AC="L", AT="N", PR="N", UI="N",
                                  VC="H", VI="H", VA="N", SC="N", SI="N", SA="N"),
    "Access Control":       dict(AV="N", AC="L", AT="N", PR="N", UI="N",
                                  VC="H", VI="L", VA="N", SC="N", SI="N", SA="N"),
    "Data Exfiltration":    dict(AV="N", AC="L", AT="N", PR="L", UI="N",
                                  VC="H", VI="N", VA="N", SC="N", SI="N", SA="N"),
    "Network Security":     dict(AV="N", AC="L", AT="P", PR="N", UI="N",
                                  VC="L", VI="L", VA="L", SC="N", SI="N", SA="N"),
    "Data Exposure":        dict(AV="N", AC="L", AT="N", PR="N", UI="N",
                                  VC="H", VI="N", VA="N", SC="N", SI="N", SA="N"),
    "Encryption":           dict(AV="N", AC="H", AT="P", PR="L", UI="N",
                                  VC="H", VI="N", VA="N", SC="N", SI="N", SA="N"),
    "Session Management":   dict(AV="N", AC="L", AT="N", PR="N", UI="P",
                                  VC="L", VI="L", VA="N", SC="N", SI="N", SA="N"),
    "Denial of Service":    dict(AV="N", AC="L", AT="N", PR="N", UI="N",
                                  VC="N", VI="N", VA="H", SC="N", SI="N", SA="N"),
    "Domain Hijacking":     dict(AV="N", AC="L", AT="N", PR="N", UI="N",
                                  VC="L", VI="H", VA="L", SC="N", SI="N", SA="N"),
    "Data Loss":            dict(AV="N", AC="L", AT="N", PR="L", UI="N",
                                  VC="N", VI="H", VA="H", SC="N", SI="N", SA="N"),
}

# Conservative default for any category outside the known taxonomy.
DEFAULT_VECTOR = dict(AV="N", AC="L", AT="P", PR="L", UI="N",
                       VC="L", VI="L", VA="L", SC="N", SI="N", SA="N")

# Keywords in the description that indicate the resource is openly/publicly
# exposed. When present, an attacker needs no extra attack step and no
# elevated privileges to reach it, so we sharpen AT/PR/UI accordingly.
_PUBLIC_EXPOSURE_KEYWORDS = (
    "public", "anonymous", "unauthenticated", "0.0.0.0/0", "allusers",
    "wildcard", "no mfa", "without mfa", "default credentials",
    "default admin",
)

_SEVERITY_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def build_vector_dict(category: str, description: str = "") -> dict:
    metrics = dict(CATEGORY_VECTORS.get(category, DEFAULT_VECTOR))
    text = str(description).lower()
    if any(k in text for k in _PUBLIC_EXPOSURE_KEYWORDS):
        metrics["AT"] = "N"
        metrics["PR"] = "N"
        metrics["UI"] = "N"
    return metrics


def build_vector_string(category: str, description: str = "") -> str:
    metrics = build_vector_dict(category, description)
    order = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
    return "CVSS:4.0/" + "/".join("{}:{}".format(m, metrics[m]) for m in order)


def score_vulnerability(category: str, description: str = "") -> dict:
    """
    Return {vector, cvss_base, severity} computed from the CVSS v4.0
    macrovector equations.
    """
    vector = build_vector_string(category, description)
    try:
        c = CVSS4(vector)
        score = float(c.base_score)
        severity = str(c.severity).upper()
    except CVSS4MandatoryError:
        # All 11 base metrics are always supplied; fail safe rather than
        # crash the pipeline on a malformed record.
        score, severity = 0.0, "NONE"
    return {"vector": vector, "cvss_base": round(score, 2), "severity": severity}


# ---------------------------------------------------------------------------
# Aggregation helpers used by the dashboard
# ---------------------------------------------------------------------------
def get_cvss_score(category: str, description: str = "") -> float:
    return score_vulnerability(category, description)["cvss_base"]


def score_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Score every record and rank highest to lowest.

    Adds cvss_vector, cvss_base, cvss_adjusted (an alias of cvss_base read
    elsewhere in the application), severity derived from the score per the
    FIRST.org rating scale, and priority_rank.
    """
    df = df.copy()
    scored = df.apply(
        lambda r: score_vulnerability(r.get("category", "UNKNOWN"), r.get("description", "")),
        axis=1, result_type="expand",
    )
    df["cvss_vector"]   = scored["vector"]
    df["cvss_base"]     = scored["cvss_base"]
    df["cvss_adjusted"] = df["cvss_base"]
    df["severity"]      = scored["severity"]

    df = df.sort_values("cvss_adjusted", ascending=False)
    df["priority_rank"] = range(1, len(df) + 1)
    return df.reset_index(drop=True)


def compute_security_debt(df: pd.DataFrame) -> float:
    col = "cvss_adjusted" if "cvss_adjusted" in df.columns else "cvss_base"
    return round(df[col].sum(), 2) if col in df.columns else 0.0


def get_severity_breakdown(df: pd.DataFrame) -> dict:
    counts = df["severity"].value_counts().to_dict()
    return {s: counts.get(s, 0) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]}


def get_category_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    col = "cvss_adjusted" if "cvss_adjusted" in df.columns else "cvss_base"
    return (
        df.groupby("category")
        .agg(count=("id", "count"), total_cvss=(col, "sum"))
        .sort_values("total_cvss", ascending=False)
        .reset_index()
    )


def get_provider_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    col = "cvss_adjusted" if "cvss_adjusted" in df.columns else "cvss_base"
    return (
        df.groupby("cloud_provider")
        .agg(count=("id", "count"), total_cvss=(col, "sum"))
        .sort_values("total_cvss", ascending=False)
        .reset_index()
    )


def verify_scoring_logic(df: pd.DataFrame) -> dict:
    scored = score_dataframe(df)
    issues = []
    for _, row in scored.iterrows():
        if not (0.0 <= row["cvss_adjusted"] <= 10.0):
            issues.append("{}: score out of range ({})".format(row["id"], row["cvss_adjusted"]))
        if row["severity"] not in _SEVERITY_ORDER:
            issues.append("{}: unrecognised severity band ({})".format(row["id"], row["severity"]))
    return {
        "total_records":   len(scored),
        "issues_found":    len(issues),
        "issue_details":   issues,
        "security_debt":   compute_security_debt(scored),
        "severity_counts": get_severity_breakdown(scored),
        "passed":          len(issues) == 0,
    }
