"""Testing and evaluation suite.

    5.1  Structural audit of generated remediation scripts
    5.2  Time efficiency against an estimated manual baseline

The 5.1 pass rate measures shell structure only. It is reported alongside the
template match rate and documentation-verified rate so that no single figure
can be read as evidence the generated commands are correct.

Template signature verification coverage (formerly reported here as 5.3) is
now run separately via tools/audit_templates.py (modules.template_audit).
"""

import re
import sys
import time
import pandas as pd
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# Estimated manual research time per finding, in minutes, by severity.
MANUAL_RESEARCH_TIME = {
    "CRITICAL": 45.0,
    "HIGH":     30.0,
    "MEDIUM":   20.0,
    "LOW":      10.0,
    "NONE":      5.0,
}

# Human review time per generated script. Every script is review-gated, so
# this cost remains after generation and is subtracted from the saving.
HITL_REVIEW_TIME_PER_SCRIPT_MIN = 3.0

_CLI_BINARIES = ("aws", "az", "gcloud", "oci", "ibmcloud", "aliyun",
                 "kubectl", "terraform", "bash", "sh", "echo", "set",
                 "if", "for", "while", "fi", "done", "then", "else", "read",
                 "export", "cat", "jq", "exit")


def _logical_commands(script_text: str) -> list:
    """Return executable commands, stripping comments and joining continuations."""
    out, buf = [], ""
    for raw in script_text.splitlines():
        line = raw.rstrip()
        if not buf and (not line.strip() or line.strip().startswith("#")):
            continue
        buf = (buf + " " + line.strip().lstrip("\\").strip()) if buf else line
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1].rstrip()
        else:
            out.append(buf)
            buf = ""
    if buf:
        out.append(buf)
    return out


def _quotes_balanced(cmd: str) -> bool:
    """Check quote balance across a command, honouring escapes and both styles."""
    in_single = in_double = False
    escaped = False
    for ch in cmd:
        if escaped:
            escaped = False
            continue
        if ch == "\\" and not in_single:
            escaped = True
        elif ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
    return not (in_single or in_double)


def syntax_audit_script(script_text: str, expect_provider: str = "") -> dict:
    """Structurally validate one generated script.

    Issues are failures. Warnings cover expected conditions such as unfilled
    {{placeholders}}, which the review workflow requires and which therefore
    never count against the pass rate.
    """
    issues, warnings = [], []
    lines = script_text.splitlines()

    if not any(l.startswith("#!/") for l in lines[:3]):
        issues.append("Missing shebang (#!/bin/bash)")

    if not any(("HUMAN-IN-THE-LOOP" in l) or ("REVIEW ONLY" in l) for l in lines):
        issues.append("Missing review warning comment")

    commands = _logical_commands(script_text)

    # A scaffold containing only comments is not a usable remediation script.
    if not commands:
        issues.append("No executable command lines (comment-only scaffold)")

    for idx, cmd in enumerate(commands, 1):
        if not _quotes_balanced(cmd):
            issues.append("Command {}: unbalanced quotes -> {}".format(idx, cmd[:70]))
        if re.search(r"<[A-Z_]{2,}>", cmd):
            issues.append("Command {}: unfilled angle-bracket placeholder".format(idx))
        head = cmd.split()[0] if cmd.split() else ""
        if head and head not in _CLI_BINARIES and not head.startswith(("$", "{", "(")):
            warnings.append("Command {}: unrecognised leading binary '{}'".format(idx, head))

    placeholders = sorted(set(re.findall(r"\{\{([A-Za-z0-9_]+)\}\}", script_text)))
    if placeholders:
        warnings.append("{} placeholder(s) require human input: {}".format(
            len(placeholders), ", ".join(placeholders[:6])))

    if expect_provider:
        from modules.template_audit import CLI_PREFIXES
        expected_bin = {v: k for k, v in CLI_PREFIXES.items()}.get(expect_provider)
        heads = {c.split()[0] for c in commands if c.split()}
        cloud_heads = heads & set(CLI_PREFIXES)
        if expected_bin and cloud_heads and expected_bin not in cloud_heads:
            issues.append("Provider mismatch: expected '{}', found {}".format(
                expected_bin, sorted(cloud_heads)))

    return {
        "valid":         len(issues) == 0,
        "issue_count":   len(issues),
        "issues":        issues,
        "warning_count": len(warnings),
        "warnings":      warnings,
        "command_count": len(commands),
        "placeholders":  placeholders,
    }


def audit_all_scripts(df: pd.DataFrame) -> dict:
    """Audit every generated script and report structure, matching and coverage."""
    from modules.mapping_engine import generate_script, _load_templates, detect_provider
    from modules.template_audit import extract_signature
    from modules import doc_verifier

    templates = _load_templates()
    cache = doc_verifier.load_cache()

    total = passed = matched = warned = 0
    failed_ids, warning_ids = [], []
    sig_seen, sig_verified = set(), set()

    for _, row in df.iterrows():
        provider = detect_provider(row)
        result = generate_script(row, templates)
        audit = syntax_audit_script(result["script_text"], expect_provider=provider)

        total += 1
        if result.get("matched"):
            matched += 1
        if audit["valid"]:
            passed += 1
        else:
            failed_ids.append({"id": row["id"], "issues": audit["issues"]})
        if audit["warning_count"]:
            warned += 1
            if len(warning_ids) < 25:
                warning_ids.append({"id": row["id"], "warnings": audit["warnings"]})

        for cmd in _logical_commands(result["script_text"]):
            parsed = extract_signature(cmd)
            if parsed:
                _, sig = parsed
                sig_seen.add(sig)
                if doc_verifier.lookup(sig, cache)["status"] == doc_verifier.STATUS_VERIFIED:
                    sig_verified.add(sig)

    accuracy = (passed / total * 100) if total else 0.0
    match_rate = (matched / total * 100) if total else 0.0
    doc_rate = (len(sig_verified) / len(sig_seen) * 100) if sig_seen else 0.0

    return {
        "total_scripts":          total,
        "passed":                 passed,
        "failed":                 total - passed,
        "accuracy_pct":           round(accuracy, 2),
        "target_pct":             90.0,
        "target_met":             accuracy >= 90.0,
        "failed_details":         failed_ids,
        "scripts_with_warnings":  warned,
        "warning_samples":        warning_ids,
        "template_matched":       matched,
        "fallback_scaffolds":     total - matched,
        "template_match_pct":     round(match_rate, 2),
        "signatures_used":        len(sig_seen),
        "signatures_doc_checked": len(sig_verified),
        "doc_verified_pct":       round(doc_rate, 2),
        "caveat": ("accuracy_pct measures shell structure only. Read it with "
                   "template_match_pct and doc_verified_pct."),
    }


def format_pct(value: float, dp: int = 2) -> str:
    """Format a percentage without rounding a sub-100 value up to 100%."""
    if value >= 100.0:
        return "100%"
    rounded = round(value, dp)
    if rounded >= 100.0:
        return ">99.99%"
    return "{:.{dp}f}%".format(rounded, dp=dp)


def time_efficiency_analysis(df: pd.DataFrame,
                             hitl_minutes: float = HITL_REVIEW_TIME_PER_SCRIPT_MIN) -> dict:
    """Compare generation time against the estimated manual baseline.

    Reports a raw figure (machine time only) and a net figure that includes
    the human review each generated script still requires. The net figure is
    the one that reflects end-to-end effort.
    """
    from modules.mapping_engine import generate_script, _load_templates
    templates = _load_templates()

    start = time.perf_counter()
    for _, row in df.iterrows():
        generate_script(row, templates)
    engine_time_s = time.perf_counter() - start
    engine_time_min = engine_time_s / 60

    n = len(df)
    manual_total = sum(
        MANUAL_RESEARCH_TIME.get(str(row.get("severity", "MEDIUM")).upper(), 20.0)
        for _, row in df.iterrows()
    )

    hitl_total = n * hitl_minutes
    assisted_total = engine_time_min + hitl_total

    raw_saved = manual_total - engine_time_min
    net_saved = manual_total - assisted_total

    raw_pct = (raw_saved / manual_total * 100) if manual_total > 0 else 0.0
    net_pct = (net_saved / manual_total * 100) if manual_total > 0 else 0.0
    speedup = (manual_total / engine_time_min) if engine_time_min > 0 else float("inf")

    return {
        "scripts_generated":        n,
        "engine_time_seconds":      round(engine_time_s, 4),
        "engine_time_minutes":      round(engine_time_min, 6),
        "manual_estimated_minutes": round(manual_total, 2),
        "raw_time_saved_minutes":   round(raw_saved, 2),
        "raw_reduction_pct":        raw_pct,
        "raw_reduction_display":    format_pct(raw_pct, 4),
        "speedup_factor":           round(speedup, 1),
        "hitl_minutes_per_script":  hitl_minutes,
        "hitl_total_minutes":       round(hitl_total, 2),
        "assisted_total_minutes":   round(assisted_total, 2),
        "net_time_saved_minutes":   round(net_saved, 2),
        "net_reduction_pct":        net_pct,
        "net_reduction_display":    format_pct(net_pct, 1),
        "caveat": ("Raw reduction compares machine time only. Net reduction "
                   "includes {:.0f} min of review per script.".format(hitl_minutes)),
    }


def _aws_azure_gcp_command_ids(df: pd.DataFrame) -> set:
    """IDs of rows whose generated script is a real (non-fallback) command
    for one of the three supported providers (AWS / Azure / GCP).

    Security debt should reflect exposure this system can actually act on -
    a row that only produced a comment-only fallback scaffold, or whose
    detected provider isn't AWS/Azure/GCP, isn't backed by a real command
    and shouldn't count toward the debt figure.
    """
    from modules.mapping_engine import generate_script, _load_templates, detect_provider
    from modules.data_loader import SUPPORTED_PROVIDERS

    templates = _load_templates()
    ids = set()
    for _, row in df.iterrows():
        provider = detect_provider(row)
        if provider not in SUPPORTED_PROVIDERS:
            continue
        result = generate_script(row, templates)
        if result.get("matched"):
            ids.add(row["id"])
    return ids


def compute_security_debt_reduction(df_before: pd.DataFrame,
                                    approved_ids: list) -> dict:
    """Compute projected security debt reduction from approved scripts.

    Scoped to rows that produced a real AWS/Azure/GCP command (see
    _aws_azure_gcp_command_ids) - rows with no matched command for one of
    the three supported providers don't contribute to the debt figure.
    """
    col = "cvss_adjusted" if "cvss_adjusted" in df_before.columns else "cvss_base"
    in_scope_ids = _aws_azure_gcp_command_ids(df_before)
    scoped = df_before[df_before["id"].isin(in_scope_ids)]

    initial_debt = scoped[col].sum()
    remediated = scoped[scoped["id"].isin(approved_ids)][col].sum()
    remaining = initial_debt - remediated
    return {
        "initial_debt":    round(initial_debt, 2),
        "remediated_debt": round(remediated, 2),
        "remaining_debt":  round(remaining, 2),
        "reduction_pct":   round((remediated / initial_debt * 100) if initial_debt > 0 else 0, 2),
        "in_scope_records": len(scoped),
        "total_records":    len(df_before),
        "note": ("Reflects scripts approved for review, not executed changes. "
                 "Scoped to records with a real matched AWS/Azure/GCP command; "
                 "unmatched/fallback records are excluded from the debt total."),
    }


def run_full_evaluation(df: pd.DataFrame) -> dict:
    """Run the complete evaluation suite."""
    return {
        "syntax_audit":    audit_all_scripts(df),
        "time_efficiency": time_efficiency_analysis(df),
    }
