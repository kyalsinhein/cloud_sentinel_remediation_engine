"""Build the documentation verification cache.

Checks every CLI signature in the template library against its official
provider source and writes the results to
templates/doc_verification_cache.json, which the application then reads
without making network calls.

    python tools/verify_signatures.py
    python tools/verify_signatures.py --provider GCP
    python tools/verify_signatures.py --force
    python tools/verify_signatures.py --dry-run

Exits 1 if any signature is reported as not_found, so the run can gate CI.
An error result is not a defect; it means verification could not complete.
"""
import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from modules.doc_verifier import verify_all, load_cache, save_cache, summarise, CACHE_PATH
from modules.template_audit import build_signature_index, PROVIDER_ORDER


def collect(provider_filter=None):
    """Return every signature to check, optionally for one provider."""
    index = build_signature_index()
    sigs = []
    for provider in PROVIDER_ORDER:
        if provider_filter and provider != provider_filter:
            continue
        sigs.extend(index.get(provider, {}).keys())
    return sorted(set(sigs))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", choices=PROVIDER_ORDER)
    ap.add_argument("--force", action="store_true",
                    help="re-check signatures even when the cache entry is fresh")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    signatures = collect(args.provider)
    print("{} signatures to consider".format(len(signatures)))

    if args.dry_run:
        for s in signatures:
            print("  " + s)
        return 0

    cache = {"generated": None, "entries": {}} if args.force else load_cache()

    def progress(i, total, result):
        mark = {"verified": "ok  ", "not_found": "FAIL",
                "error": "?   ", "unsupported": "skip"}.get(result["status"], "?   ")
        print("  [{:>3}/{}] {} {}".format(i, total, mark, result["signature"]))

    cache = verify_all(signatures, cache=cache, progress=progress)
    save_cache(cache)

    results = [cache["entries"][s] for s in signatures if s in cache["entries"]]
    summary = summarise(results)

    print("\n=== SUMMARY ===")
    print("cache: {}".format(CACHE_PATH))
    for status, n in sorted(summary["counts"].items()):
        print("  {:<12} {}".format(status, n))
    print("  verified     {}%".format(summary["verified_pct"]))

    if summary["defects"]:
        print("\n=== DEFECTS ===")
        for d in summary["defects"]:
            print("  {}\n      {}\n      {}".format(d["signature"], d["detail"], d["source"]))

    if summary["undetermined"]:
        print("\n=== UNDETERMINED ({}) ===".format(len(summary["undetermined"])))
        for u in summary["undetermined"][:10]:
            print("  {} - {}".format(u["signature"], u["detail"]))

    return 1 if summary["defects"] else 0


if __name__ == "__main__":
    sys.exit(main())
