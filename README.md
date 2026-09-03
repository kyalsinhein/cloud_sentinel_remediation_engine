# Cloud Sentinel Remediation Engine

A human-in-the-loop (HITL) pipeline that takes a dataset of cloud
misconfiguration findings (AWS / Azure / GCP), scores them with CVSS v4.0,
maps each one to a validated CLI remediation template, and generates a
review-only shell script per finding. No step executes changes against a
live environment — every generated script is explicitly for review, and
every CLI command in the template library is checked against the relevant
provider's official documentation before being trusted.

Online Demo : https://cloudsentinelremediationengine-57tvbxmbeq4qlp5yvmp4gs.streamlit.app/

## Pipeline

1. **Load data** (`modules/data_loader.py`) : reads the bundled JSONL
   dataset, normalises columns, drops unusable/out-of-scope records, and
   *flags* (rather than silently drops) data-quality issues so a human can
   review them.
2. **Score & map** (`modules/cvss_scorer.py`) : derives a CVSS v4.0 base
   vector per finding from its category (using the official FIRST.org
   macrovector tables via the `cvss` package) and computes severity.
3. **Review & remediate (HITL)** : a human reviews and approves findings
   before scripts are generated for them.
4. **Generate remediation script** (`modules/mapping_engine.py`) : matches
   each finding to the most specific applicable CLI template and populates
   it with the finding's resource metadata. Falls back to a manual-review
   scaffold when no template matches, rather than guessing.
5. **Run evaluation** (`modules/evaluator.py`) : audits the structural
   validity of generated scripts and estimates review-time savings against
   a manual-research baseline.



## Setup

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Running the tests

```bash
pip install pytest
pytest tests/ -v
```

