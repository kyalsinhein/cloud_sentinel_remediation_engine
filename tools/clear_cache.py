"""Clear the project's caches.

    python tools/clear_cache.py --all
    python tools/clear_cache.py --verification
    python tools/clear_cache.py --pycache
    python tools/clear_cache.py --dry-run --all

The verification cache is evidence: it records which command signatures were
confirmed, against which URL, on which date. Deleting it discards that record
and requires a full re-run. To re-check signatures while keeping the file,
use `python tools/verify_signatures.py --force` instead.
"""
import argparse
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

VERIFICATION_CACHE = PROJECT_ROOT / "templates" / "doc_verification_cache.json"


def clear_verification(dry_run: bool) -> None:
    """Delete the documentation verification cache."""
    if not VERIFICATION_CACHE.exists():
        print("verification cache: already absent")
        return
    size_kb = VERIFICATION_CACHE.stat().st_size / 1024
    if dry_run:
        print("verification cache: would delete {} ({:.1f} KB)".format(
            VERIFICATION_CACHE, size_kb))
        return
    VERIFICATION_CACHE.unlink()
    print("verification cache: deleted ({:.1f} KB)".format(size_kb))
    print("  re-run: python tools/verify_signatures.py")


def clear_pycache(dry_run: bool) -> None:
    """Remove __pycache__ directories and stray .pyc files."""
    dirs = [p for p in PROJECT_ROOT.rglob("__pycache__") if p.is_dir()]
    pyc = [p for p in PROJECT_ROOT.rglob("*.pyc") if p.is_file()]
    if not dirs and not pyc:
        print("bytecode cache: nothing to remove")
        return
    if dry_run:
        print("bytecode cache: would remove {} dir(s), {} .pyc file(s)".format(
            len(dirs), len(pyc)))
        return
    for d in dirs:
        shutil.rmtree(d, ignore_errors=True)
    for f in pyc:
        f.unlink(missing_ok=True)
    print("bytecode cache: removed {} dir(s), {} .pyc file(s)".format(
        len(dirs), len(pyc)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--verification", action="store_true")
    ap.add_argument("--pycache", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not (args.all or args.verification or args.pycache):
        ap.print_help()
        return 1

    if args.all or args.verification:
        clear_verification(args.dry_run)
    if args.all or args.pycache:
        clear_pycache(args.dry_run)

    print("\nNot cleared by this script:")
    print("  botocore service models - part of the installed package;")
    print("    reinstall with: pip install --upgrade --force-reinstall botocore")
    print("  in-process lru_cache    - discarded when the process exits")
    print("  Streamlit session state - use 'Start Over' in the sidebar,")
    print("    or restart the server")
    return 0


if __name__ == "__main__":
    sys.exit(main())
