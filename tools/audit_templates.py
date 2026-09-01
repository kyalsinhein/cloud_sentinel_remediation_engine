"""Print the template signature coverage report.

    python tools/audit_templates.py
    python tools/audit_templates.py --json
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from modules.template_audit import audit_template_coverage, print_report

if __name__ == "__main__":
    report = audit_template_coverage()
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
