"""Command-signature coverage audit across the remediation template library.

Extracts every CLI command signature used by the templates, then reports how
many have been confirmed against official provider sources via
modules.doc_verifier.

Coverage is reported per provider because the three backends differ in
authority, and defects (the source says a command does not exist) are kept
separate from undetermined results (verification could not be completed).
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from modules.mapping_engine import _load_templates
from modules.verified_signatures import (
    VERIFIED_SIGNATURES, PROVIDER_DOC_ROOTS, KNOWN_PARSING_ARTIFACTS,
)
from modules.data_loader import SUPPORTED_PROVIDERS
from modules import doc_verifier

# Wider than SUPPORTED_PROVIDERS so a stray command for an out-of-scope
# provider is still parsed and visible in the index.
CLI_PREFIXES = {
    "aws": "AWS", "az": "Azure", "gcloud": "GCP",
    "oci": "OracleCloud", "ibmcloud": "IBMCloud", "aliyun": "AlibabaCloud",
}

PROVIDER_ORDER = list(SUPPORTED_PROVIDERS)

VERIFICATION_SOURCE = {
    "AWS":   "botocore service models (offline)",
    "GCP":   "gcloud reference site (cached)",
    "Azure": "az docs group pages (cached)",
}


def join_continuations(lines):
    """Join backslash-continued lines into single logical commands."""
    joined, buf = [], ""
    for line in lines:
        stripped = line.rstrip()
        if buf:
            buf += " " + stripped.strip().lstrip("\\").strip()
        elif stripped.strip().startswith("#") or not stripped.strip():
            continue
        else:
            buf = stripped
        if buf.endswith("\\"):
            buf = buf[:-1].rstrip()
        else:
            joined.append(buf)
            buf = ""
    if buf:
        joined.append(buf)
    return joined


def extract_signature(cmd: str):
    """Reduce a command to (provider, signature), or None if not a cloud CLI.

    The signature is the leading verb path with flags and {{placeholders}}
    stripped, capped at five tokens.
    """
    tokens = cmd.split()
    if not tokens or tokens[0] not in CLI_PREFIXES:
        return None
    provider = CLI_PREFIXES[tokens[0]]
    sig_tokens = [tokens[0]]
    for t in tokens[1:]:
        if t.startswith("-") or t.startswith("{{"):
            break
        sig_tokens.append(t)
    return provider, " ".join(sig_tokens[:5])


def build_signature_index(templates: dict = None) -> dict:
    """Build {provider: {signature: {count, example, keys}}} over templates.

    The count is reuse frequency; high-reuse signatures affect the most
    generated scripts and are worth verifying first.
    """
    if templates is None:
        templates = _load_templates()

    signatures = {}
    for key, tpl in templates.items():
        for cmd in join_continuations(tpl.get("commands", [])):
            parsed = extract_signature(cmd)
            if not parsed:
                continue
            provider, sig = parsed
            d = signatures.setdefault(provider, {})
            entry = d.setdefault(sig, {"count": 0, "example": cmd, "keys": set()})
            entry["count"] += 1
            entry["keys"].add(key)
    return signatures


def audit_template_coverage(templates: dict = None, top_n: int = 5) -> dict:
    """Return a JSON-serialisable verification coverage report."""
    if templates is None:
        templates = _load_templates()

    index = build_signature_index(templates)
    cache = doc_verifier.load_cache()

    providers = {}
    total_sigs = 0
    total_verified = 0

    for provider in PROVIDER_ORDER:
        sigs = index.get(provider, {})
        verified_set = VERIFIED_SIGNATURES.get(provider, set())
        artifacts = KNOWN_PARSING_ARTIFACTS.get(provider, {})
        checks = {s: doc_verifier.lookup(s, cache) for s in sigs if s not in artifacts}

        def covered(s):
            if s in artifacts:
                return False
            return (checks[s]["status"] == doc_verifier.STATUS_VERIFIED
                    or s in verified_set)

        confirmed = sorted(s for s in sigs if s not in artifacts and covered(s))
        unverified = sorted((s for s in sigs if s not in artifacts and not covered(s)),
                            key=lambda s: -sigs[s]["count"])
        defects = [{"signature": s, "detail": c["detail"],
                    "source": c.get("source", "")}
                   for s, c in checks.items()
                   if c["status"] == doc_verifier.STATUS_NOT_FOUND]
        undetermined = [s for s, c in checks.items()
                        if c["status"] in (doc_verifier.STATUS_ERROR, "stale")]
        parsing_artifacts = [{"signature": s, "detail": reason}
                             for s, reason in artifacts.items() if s in sigs]

        total = len(sigs)
        total_sigs += total
        total_verified += len(confirmed)

        providers[provider] = {
            "total_signatures":    total,
            "verified_count":      len(confirmed),
            "unverified_count":    len(unverified),
            "coverage_pct":        round(len(confirmed) / total * 100, 1) if total else 0.0,
            "doc_root":            PROVIDER_DOC_ROOTS.get(provider, ""),
            "verification_source": VERIFICATION_SOURCE.get(provider, ""),
            "doc_verified":        sum(1 for c in checks.values()
                                       if c["status"] == doc_verifier.STATUS_VERIFIED),
            "manual_override":     sum(1 for s in sigs if s in verified_set),
            "undetermined_count":  len(undetermined),
            "defects":             defects,
            "parsing_artifacts":   parsing_artifacts,
            "verified":            confirmed,
            "top_unverified": [
                {"signature": s,
                 "reuse_count": sigs[s]["count"],
                 "example": sigs[s]["example"],
                 "template_keys": sorted(sigs[s]["keys"])[:5]}
                for s in unverified[:top_n]
            ],
            "all_signatures": [
                {"signature": s, "reuse_count": sigs[s]["count"],
                 "verified": covered(s)}
                for s in sorted(sigs, key=lambda s: (-sigs[s]["count"], s))
            ],
        }

    return {
        "templates_audited":    len(templates),
        "total_signatures":     total_sigs,
        "total_verified":       total_verified,
        "total_unverified":     total_sigs - total_verified,
        "overall_coverage_pct": round(total_verified / total_sigs * 100, 1) if total_sigs else 0.0,
        "defect_count":         sum(len(p["defects"]) for p in providers.values()),
        "undetermined_count":   sum(p["undetermined_count"] for p in providers.values()),
        "parsing_artifact_count": sum(len(p["parsing_artifacts"]) for p in providers.values()),
        "cache_generated":      cache.get("generated"),
        "providers":            providers,
        "disclaimer": ("Coverage counts command paths confirmed against official "
                       "provider sources. Flags, argument values and remediation "
                       "suitability are not checked."),
    }


def print_report(report: dict = None) -> None:
    """Print the coverage report to stdout."""
    if report is None:
        report = audit_template_coverage()

    for provider in PROVIDER_ORDER:
        p = report["providers"][provider]
        print("\n=== {}: {} unique command signatures ===".format(
            provider, p["total_signatures"]))
        for row in sorted(p["all_signatures"], key=lambda r: r["signature"]):
            mark = "ok " if row["verified"] else "   "
            print("  {}[{:>3}x] {}".format(mark, row["reuse_count"], row["signature"]))

    print("\n\n=== VERIFICATION COVERAGE ===")
    for provider in PROVIDER_ORDER:
        p = report["providers"][provider]
        if not p["total_signatures"]:
            continue
        print("{}: {}/{} verified ({}%) via {}".format(
            provider, p["verified_count"], p["total_signatures"],
            p["coverage_pct"], p["verification_source"]))
        for d in p["defects"]:
            print("  DEFECT: {} - {}".format(d["signature"], d["detail"]))
        for a in p["parsing_artifacts"]:
            print("  ARTIFACT (not a defect): {} - {}".format(
                a["signature"], a["detail"]))
        if p["top_unverified"]:
            print("  Highest-reuse unverified:")
            for row in p["top_unverified"]:
                print("    [{}x] {}".format(row["reuse_count"], row["signature"]))

    print("\nOVERALL: {}/{} ({}%), {} defect(s), {} undetermined".format(
        report["total_verified"], report["total_signatures"],
        report["overall_coverage_pct"], report["defect_count"],
        report["undetermined_count"]))
    print(report["disclaimer"])


if __name__ == "__main__":
    print_report()
