"""Verification of CLI command signatures against official provider sources.

Backends, in descending order of authority:

    AWS     botocore service models, offline (modules.aws_cli_schema)
    GCP     docs.cloud.google.com/sdk/gcloud/reference/<group>/<command>
    Azure   learn.microsoft.com/en-us/cli/azure/<group>, per-command anchors

The Azure backend parses HTML rather than a schema, so it is the least robust
of the three; parse failures are reported as errors, never as verified.

Results are cached to templates/doc_verification_cache.json by
tools/verify_signatures.py. The application reads the cache and never makes
network calls. Entries older than CACHE_MAX_AGE_DAYS report as stale.

Scope: command paths only. No backend checks flags, argument values, or
whether a command is the correct remediation for a given finding.
"""

import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from modules import aws_cli_schema

CACHE_PATH = _ROOT / "templates" / "doc_verification_cache.json"
CACHE_MAX_AGE_DAYS = 90

GCP_DOC_BASE = "https://docs.cloud.google.com/sdk/gcloud/reference"
AZURE_DOC_BASE = "https://learn.microsoft.com/en-us/cli/azure"

REQUEST_DELAY_S = 0.5
REQUEST_TIMEOUT_S = 15

STATUS_VERIFIED = "verified"
STATUS_NOT_FOUND = "not_found"
STATUS_ERROR = "error"
STATUS_UNSUPPORTED = "unsupported"

_USER_AGENT = "cloud-sentinel-signature-verifier"

# Signature extraction stops at flags and {{placeholders}}, so bare positional
# arguments can end up inside a signature. These patterns identify them.
_ARG_LIKE = re.compile(r"""[./:={}'"]|^[A-Z][A-Z0-9_]*$|^gs://|^oss://""")


def looks_like_argument(token: str) -> bool:
    """True when a token is a resource id or URI rather than a subcommand."""
    return bool(_ARG_LIKE.search(token))


def split_signature(signature: str):
    """Split "gcloud sql instances patch" into (binary, groups, command)."""
    tokens = signature.split()
    if len(tokens) < 2:
        return None
    return tokens[0], tokens[1:-1], tokens[-1]


def candidate_paths(groups: list, command: str):
    """Yield (groups, command, dropped) from the full path inward.

    Only argument-shaped trailing tokens are peeled off. A plausible
    subcommand is never dropped, so a typo cannot fall back to its parent
    group page and be reported as verified.
    """
    parts = groups + [command]
    dropped = []
    while len(parts) >= 2:
        yield parts[:-1], parts[-1], list(dropped)
        if not looks_like_argument(parts[-1]):
            return
        dropped.insert(0, parts[-1])
        parts = parts[:-1]


def verify_aws(signature: str) -> dict:
    """Verify an AWS signature via the offline botocore models."""
    r = aws_cli_schema.verify_aws_signature(signature)
    mapping = {
        "verified":    STATUS_VERIFIED,
        "bad_command": STATUS_NOT_FOUND,
        "bad_service": STATUS_NOT_FOUND,
        "unavailable": STATUS_ERROR,
        "not_aws":     STATUS_UNSUPPORTED,
    }
    return {
        "signature": signature,
        "provider":  "AWS",
        "status":    mapping.get(r["status"], STATUS_ERROR),
        "source":    "botocore service model (offline)",
        "detail":    r["detail"],
    }


def verify_gcp(signature: str, session=None) -> dict:
    """Verify a gcloud signature against its reference page.

    The reference URL path equals the command path, so page existence is the
    check. A 200 response must also name the command, which rejects soft-404
    redirects to search pages.
    """
    import requests
    parsed = split_signature(signature)
    if not parsed or parsed[0] != "gcloud":
        return {"signature": signature, "provider": "GCP",
                "status": STATUS_UNSUPPORTED, "source": "",
                "detail": "not a gcloud command"}

    _, groups, command = parsed
    get = (session or requests).get
    last = None

    for cand_groups, cand_cmd, dropped in candidate_paths(groups, command):
        url = "/".join([GCP_DOC_BASE] + cand_groups + [cand_cmd])
        resolved = " ".join(["gcloud"] + cand_groups + [cand_cmd])
        note = (" (trailing argument{} {} ignored)".format(
            "s" if len(dropped) > 1 else "",
            ", ".join(repr(d) for d in dropped)) if dropped else "")

        try:
            resp = get(url, timeout=REQUEST_TIMEOUT_S,
                       headers={"User-Agent": _USER_AGENT})
        except Exception as e:
            return {"signature": signature, "provider": "GCP",
                    "status": STATUS_ERROR, "source": url,
                    "detail": "request failed: {}".format(e)}

        if resp.status_code == 200:
            if resolved.lower() in resp.text.lower():
                return {"signature": signature, "provider": "GCP",
                        "status": STATUS_VERIFIED, "source": url,
                        "resolved": resolved,
                        "detail": "reference page names the command" + note}
            last = {"signature": signature, "provider": "GCP",
                    "status": STATUS_ERROR, "source": url, "resolved": resolved,
                    "detail": "200 but page does not name the command"}
        elif resp.status_code == 404:
            last = {"signature": signature, "provider": "GCP",
                    "status": STATUS_NOT_FOUND, "source": url,
                    "resolved": resolved,
                    "detail": "no reference page for '{}'".format(resolved)}
        else:
            last = {"signature": signature, "provider": "GCP",
                    "status": STATUS_ERROR, "source": url, "resolved": resolved,
                    "detail": "unexpected HTTP {}".format(resp.status_code)}
        time.sleep(REQUEST_DELAY_S)

    return last or {"signature": signature, "provider": "GCP",
                    "status": STATUS_ERROR, "source": "",
                    "detail": "no candidate path to check"}


def verify_azure(signature: str, session=None) -> dict:
    """Verify an az signature by locating its anchor on the group docs page."""
    import requests
    parsed = split_signature(signature)
    if not parsed or parsed[0] != "az":
        return {"signature": signature, "provider": "Azure",
                "status": STATUS_UNSUPPORTED, "source": "",
                "detail": "not an az command"}

    _, groups, command = parsed
    if not groups:
        return {"signature": signature, "provider": "Azure",
                "status": STATUS_UNSUPPORTED, "source": "",
                "detail": "top-level command has no group page"}

    url = "{}/{}?view=azure-cli-latest".format(AZURE_DOC_BASE, "/".join(groups))
    anchor = "az-{}-{}".format("-".join(groups), command)
    get = (session or requests).get

    try:
        resp = get(url, timeout=REQUEST_TIMEOUT_S,
                   headers={"User-Agent": _USER_AGENT})
    except Exception as e:
        return {"signature": signature, "provider": "Azure",
                "status": STATUS_ERROR, "source": url,
                "detail": "request failed: {}".format(e)}

    if resp.status_code == 404:
        return {"signature": signature, "provider": "Azure",
                "status": STATUS_NOT_FOUND, "source": url,
                "detail": "no docs page for group '{}'".format(" ".join(groups))}
    if resp.status_code != 200:
        return {"signature": signature, "provider": "Azure",
                "status": STATUS_ERROR, "source": url,
                "detail": "unexpected HTTP {}".format(resp.status_code)}

    body = resp.text
    if re.search(r'id=["\']' + re.escape(anchor) + r'["\']', body, re.IGNORECASE):
        return {"signature": signature, "provider": "Azure",
                "status": STATUS_VERIFIED, "source": url + "#" + anchor,
                "detail": "anchor found on group page"}

    # No az-* anchors at all means the page layout changed and parsing failed,
    # which is an error rather than evidence the command is missing.
    if not re.search(r'id=["\']az-[a-z0-9-]+["\']', body, re.IGNORECASE):
        return {"signature": signature, "provider": "Azure",
                "status": STATUS_ERROR, "source": url,
                "detail": "no az-* anchors found; docs layout may have changed"}

    return {"signature": signature, "provider": "Azure",
            "status": STATUS_NOT_FOUND, "source": url,
            "detail": "group page lacks anchor '{}'".format(anchor)}


_BACKENDS = {"aws": verify_aws, "gcloud": verify_gcp, "az": verify_azure}


def verify_signature(signature: str, session=None) -> dict:
    """Dispatch a signature to the backend for its CLI binary."""
    binary = signature.split()[0] if signature.split() else ""
    fn = _BACKENDS.get(binary)
    if not fn:
        return {"signature": signature, "provider": "Unknown",
                "status": STATUS_UNSUPPORTED, "source": "",
                "detail": "no backend for '{}'".format(binary)}
    return fn(signature) if fn is verify_aws else fn(signature, session=session)


def load_cache(path: Path = CACHE_PATH) -> dict:
    """Load the verification cache, returning an empty one if absent."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"generated": None, "entries": {}}


def save_cache(cache: dict, path: Path = CACHE_PATH) -> None:
    """Write the verification cache to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, indent=2, sort_keys=True)


def _age_days(iso: str) -> float:
    try:
        then = datetime.fromisoformat(iso)
        if then.tzinfo is None:
            then = then.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - then).total_seconds() / 86400
    except Exception:
        return float("inf")


def lookup(signature: str, cache: dict = None) -> dict:
    """Read-only verification used by the application.

    AWS is re-checked directly because it is offline and instant. GCP and
    Azure come from the cache, and verified entries past CACHE_MAX_AGE_DAYS
    are downgraded to stale.
    """
    if signature.startswith("aws "):
        return verify_aws(signature)

    cache = cache if cache is not None else load_cache()
    entry = cache.get("entries", {}).get(signature)
    if not entry:
        return {"signature": signature, "provider": "Unknown",
                "status": STATUS_ERROR, "source": "",
                "detail": "not in cache; run tools/verify_signatures.py"}

    age = _age_days(entry.get("checked_on", ""))
    if entry.get("status") == STATUS_VERIFIED and age > CACHE_MAX_AGE_DAYS:
        return dict(entry, status="stale",
                    detail="verified {} days ago".format(int(age)))
    return entry


def verify_all(signatures, cache: dict = None, delay: float = REQUEST_DELAY_S,
               progress=None) -> dict:
    """Verify signatures over the network and return an updated cache.

    Fresh verified entries are skipped so repeat runs only request what is new
    or stale.
    """
    import requests
    cache = cache if cache is not None else load_cache()
    entries = dict(cache.get("entries", {}))
    session = requests.Session()

    todo = []
    for sig in sorted(set(signatures)):
        if sig.startswith("aws "):
            todo.append(sig)
            continue
        prev = entries.get(sig)
        if (prev and prev.get("status") == STATUS_VERIFIED
                and _age_days(prev.get("checked_on", "")) <= CACHE_MAX_AGE_DAYS):
            continue
        todo.append(sig)

    for i, sig in enumerate(todo, 1):
        result = verify_signature(sig, session=session)
        result["checked_on"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        entries[sig] = result
        if progress:
            progress(i, len(todo), result)
        if not sig.startswith("aws "):
            time.sleep(delay)

    return {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "cache_max_age_days": CACHE_MAX_AGE_DAYS,
            "entries": entries}


def summarise(results) -> dict:
    """Aggregate verification results into counts, defects and unknowns."""
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    total = len(results)
    verified = counts.get(STATUS_VERIFIED, 0)
    return {
        "total":        total,
        "counts":       counts,
        "verified_pct": round(verified / total * 100, 1) if total else 0.0,
        "defects":      [r for r in results if r["status"] == STATUS_NOT_FOUND],
        "undetermined": [r for r in results
                         if r["status"] in (STATUS_ERROR, "stale")],
    }
