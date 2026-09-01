"""AWS CLI signature validation against botocore's bundled service models.

botocore ships a machine-readable model per AWS service, and the AWS CLI
derives its subcommand names from the operation names in those models. This
module reuses that data to confirm a command path exists, offline.

Scope: service and operation names only. Flags, argument values and whether a
command is the appropriate remediation are not checked.

botocore is an optional dependency; without it every check returns
"unavailable" and callers fall back to the cached documentation results.
"""

import re
from functools import lru_cache

try:
    import botocore.session
    from botocore.exceptions import UnknownServiceError
    _BOTOCORE_AVAILABLE = True
except ImportError:
    _BOTOCORE_AVAILABLE = False

# AWS CLI command names that differ from the botocore service id.
_CLI_TO_BOTOCORE = {
    "s3api":         "s3",
    "configservice": "config",
    "deploy":        "codedeploy",
}


def is_available() -> bool:
    """True when botocore is importable and checks can run."""
    return _BOTOCORE_AVAILABLE


def _xform(operation_name: str) -> str:
    """Convert a CamelCase operation name to its kebab-case CLI subcommand."""
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1-\2", operation_name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", s).lower()


@lru_cache(maxsize=None)
def _subcommands(cli_service: str):
    """Return the valid CLI subcommands for a service, or None if unknown."""
    if not _BOTOCORE_AVAILABLE:
        return None
    service = _CLI_TO_BOTOCORE.get(cli_service, cli_service)
    try:
        model = botocore.session.get_session().get_service_model(service)
    except (UnknownServiceError, Exception):
        return None
    return frozenset(_xform(op) for op in model.operation_names)


def verify_aws_signature(signature: str) -> dict:
    """Check one signature such as "aws organizations create-policy".

    Returns a dict whose "status" is one of:
        verified    service and subcommand both exist in the model
        bad_command service exists, subcommand does not
        bad_service no such AWS service
        unavailable botocore not installed
        not_aws     signature is not an `aws` command
    """
    tokens = signature.split()
    if not tokens or tokens[0] != "aws":
        return {"signature": signature, "status": "not_aws", "detail": ""}
    if not _BOTOCORE_AVAILABLE:
        return {"signature": signature, "status": "unavailable",
                "detail": "botocore not installed"}
    if len(tokens) < 3:
        return {"signature": signature, "status": "bad_command",
                "detail": "signature has no subcommand"}

    service = tokens[1]
    subcommand = "-".join(tokens[2:]) if len(tokens) > 3 else tokens[2]

    subs = _subcommands(service)
    if subs is None:
        return {"signature": signature, "status": "bad_service",
                "detail": "no botocore model for service '{}'".format(service)}
    if subcommand in subs:
        return {"signature": signature, "status": "verified",
                "detail": "found in botocore model for '{}'".format(service)}

    close = sorted(s for s in subs if s.split("-")[0] == subcommand.split("-")[0])[:4]
    return {"signature": signature, "status": "bad_command",
            "detail": "'{}' not an operation of '{}'{}".format(
                subcommand, service,
                "; similar: " + ", ".join(close) if close else "")}


def verify_signature_set(signatures) -> dict:
    """Check an iterable of signatures and return counts plus per-item rows."""
    rows = [verify_aws_signature(s) for s in signatures]
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {
        "botocore_available": _BOTOCORE_AVAILABLE,
        "checked":            len(rows),
        "counts":             counts,
        "results":            rows,
        "failures":           [r for r in rows
                               if r["status"] in ("bad_command", "bad_service")],
    }
