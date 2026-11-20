# -*- coding: utf-8 -*-
"""Cloud Sentinel Remediation Engine - Streamlit dashboard.

A five-step wizard. Each step's controls appear in both a top action bar and
the sidebar so they are always reachable, and only one step's controls are on
screen at a time. Completing a step locks it: inputs are replaced by a summary
with an unlock action to redo that stage.

Steps:
    1. Load data
    2. Score and map (CVSS v4.0)
    3. Review and remediate
    4. Generate remediation script
    5. Run evaluation
"""

import io
import json
import sys
import os
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
os.chdir(_HERE)

import pandas as pd
import streamlit as st

from modules.data_loader    import load_and_clean_from_local_jsonl, get_flagged_records, DEFAULT_DATASET_PATH
from modules.cvss_scorer    import (score_dataframe, compute_security_debt,
                                    get_severity_breakdown, get_category_breakdown,
                                    get_provider_breakdown, verify_scoring_logic)
from modules.mapping_engine import (generate_script, process_dataframe, _load_templates,
                                    templates_health_check)
from modules.evaluator      import (run_full_evaluation, compute_security_debt_reduction)

# Page config
st.set_page_config(
    page_title="Cloud Sentinel Remediation Engine",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)

STEP_LABELS = [
    "Load Data",
    "Score & Map (CVSS v4.0)",
    "Review & Remediate (HITL)",
    "Generate Remediation Script",
    "Run Evaluation",
]
N_STEPS = len(STEP_LABELS)

# Session state
_DEFAULTS = {
    "df":                    None,
    "scored_df":             None,
    "approved":              set(),
    "templates":             None,
    "data_source":           None,
    "cleaning_report":       None,
    "eval_report":           None,
    "current_step":          0,
    "reviewed_confirmed":    False,   # step 2 completed
    "remediation_confirmed": False,   # step 3 completed
    "selected_vuln_id":      None,
}
for key, default in _DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = default

for i in range(N_STEPS):
    st.session_state.setdefault("unlock_{}".format(i), False)


# Step lock / navigation helpers
def lock_all_steps():
    for i in range(N_STEPS):
        st.session_state["unlock_{}".format(i)] = False


def is_unlocked(step: int) -> bool:
    return st.session_state.get("unlock_{}".format(step), False)


def make_unlock(step: int):
    def _fn():
        st.session_state["unlock_{}".format(step)] = True
        st.rerun()
    return _fn


def make_lock(step: int):
    def _fn():
        st.session_state["unlock_{}".format(step)] = False
        st.rerun()
    return _fn


def make_goto(step: int):
    def _fn():
        lock_all_steps()
        st.session_state.current_step = step
        st.rerun()
    return _fn


def goto(step: int):
    make_goto(step)()


def reset_pipeline():
    for key, default in _DEFAULTS.items():
        st.session_state[key] = set() if key == "approved" else default
    lock_all_steps()


# CSS
st.markdown("""
<style>
/* Hide Streamlit's built-in header toolbar and Deploy button. Also set in
   .streamlit/config.toml; selectors are duplicated because the test ids
   changed across Streamlit versions. */
[data-testid="stToolbar"]        { display: none !important; }
[data-testid="stAppDeployButton"]{ display: none !important; }
.stDeployButton                  { display: none !important; }
[data-testid="stStatusWidget"]   { visibility: hidden; }
#MainMenu                        { visibility: hidden; }
footer                           { visibility: hidden; }
header [data-testid="baseButton-header"] { display: none !important; }

[data-testid="metric-container"] {
    background: #1e2130; border: 1px solid #2d3148;
    border-radius: 8px; padding: 16px;
}
.critical { color: #ff4b4b; font-weight: bold; }
.high     { color: #ffa500; font-weight: bold; }
.medium   { color: #ffd700; font-weight: bold; }
.low      { color: #00d4ff; font-weight: bold; }

/* ── Horizontal step tracker ─────────────────────────────────────────── */
.step-tracker {
    display: flex; align-items: flex-start; justify-content: center;
    gap: 0; margin: 4px auto 18px auto; max-width: 1000px;
}
.step-item {
    display: flex; flex-direction: column; align-items: center;
    flex: 1; position: relative; text-align: center;
}
.step-circle {
    width: 38px; height: 38px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-weight: 700; font-size: 15px; z-index: 2;
    border: 2px solid #3a3f5c; background: #1e2130; color: #9aa0c3;
    transition: all 0.2s ease;
}
.step-item.done .step-circle {
    background: #16a34a; border-color: #16a34a; color: white;
}
.step-item.active .step-circle {
    background: #3b82f6; border-color: #3b82f6; color: white;
    box-shadow: 0 0 0 4px rgba(59,130,246,0.25);
}
.step-item.active.done .step-circle {
    background: #16a34a; border-color: #16a34a;
    box-shadow: 0 0 0 4px rgba(22,163,74,0.28);
}
.step-label {
    margin-top: 7px; font-size: 12.5px; color: #b8bcd6; max-width: 145px;
    line-height: 1.25;
}
.step-item.done .step-label   { color: #16a34a; font-weight: 600; }
.step-item.active .step-label { color: #3b82f6; font-weight: 600; }
.step-item.active.done .step-label { color: #16a34a; }
.step-connector {
    position: absolute; top: 19px; left: -50%; width: 100%; height: 2px;
    background: #3a3f5c; z-index: 1;
}
.step-item.done .step-connector { background: #16a34a; }
.step-item:first-child .step-connector { display: none; }

/* ── Step action bar (main area, top of each step) ────────────────────── */
.action-bar-wrap {
    background: #171a29; border: 1px solid #2d3148;
    border-radius: 10px; padding: 10px 14px 2px 14px; margin-bottom: 6px;
}
.action-bar-title {
    font-size: 11.5px; letter-spacing: 0.08em; text-transform: uppercase;
    color: #7f86ad; margin-bottom: 6px;
}

.done-banner {
    background: #12271c; border: 1px solid rgba(22,163,74,0.35);
    border-radius: 8px; padding: 14px 18px; margin: 10px 0 16px 0;
    color: #7fe3a3; font-size: 14.5px;
}
.done-banner b { color: #b6f5cd; }
</style>
""", unsafe_allow_html=True)


def render_step_tracker(current_step: int, done_flags: list):
    html = ['<div class="step-tracker">']
    for i, label in enumerate(STEP_LABELS):
        classes = []
        if done_flags[i]:
            classes.append("done")
        if i == current_step:
            classes.append("active")
        mark = "&#10003;" if done_flags[i] else str(i + 1)
        html.append(
            '<div class="step-item {cls}">'
            '<div class="step-connector"></div>'
            '<div class="step-circle">{mark}</div>'
            '<div class="step-label">{label}</div>'
            '</div>'.format(cls=" ".join(classes), mark=mark, label=label)
        )
    html.append("</div>")
    st.markdown("".join(html), unsafe_allow_html=True)


# Action helpers
# An "action" is a dict:
#   {"label", "key", "type": "primary"|"secondary", "disabled": bool,
#    "on_click": callable}                          -> a button
#   {"label", "key", "download": {"data","file_name","mime"}}  -> download button
def act(label, key, on_click, type="secondary", disabled=False):
    return {"label": label, "key": key, "type": type,
            "disabled": disabled, "on_click": on_click}


def dl(label, key, data, file_name, mime="text/x-sh"):
    return {"label": label, "key": key,
            "download": {"data": data, "file_name": file_name, "mime": mime}}


def _render_action(a, container, suffix):
    widget_key = "{}{}".format(a["key"], suffix)
    if "download" in a:
        container.download_button(
            a["label"], data=a["download"]["data"],
            file_name=a["download"]["file_name"], mime=a["download"]["mime"],
            key=widget_key, use_container_width=True,
        )
        return
    if container.button(a["label"], key=widget_key, type=a.get("type", "secondary"),
                        disabled=a.get("disabled", False), use_container_width=True):
        a["on_click"]()


def render_step_actions(actions):
    """
    Step-specific actions (run, approve, download, redo...) rendered as a
    horizontal bar at the TOP of the step's own page area.
    Navigation (Back / Continue) does NOT go here - it lives in the sidebar.
    """
    if not actions:
        return
    st.markdown('<div class="action-bar-wrap">'
                '<div class="action-bar-title">Actions for this step</div>',
                unsafe_allow_html=True)
    cols = st.columns(max(len(actions), 3))
    for a, col in zip(actions, cols):
        with col:
            _render_action(a, st, "_top")
    st.markdown('</div>', unsafe_allow_html=True)
    st.write("")


def render_sidebar_actions(actions):
    """Navigation only (Back / Continue), kept uncluttered in the sidebar."""
    with st.sidebar:
        st.markdown("### Navigation")
        if not actions:
            st.caption("No navigation available.")
        for a in actions:
            _render_action(a, st.sidebar, "_sb")
        st.divider()


def _render_cleaning_report(report: dict):
    """Step-0 data-cleaning summary - always shown, never silent."""
    st.markdown("##### Data Cleaning Report")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Raw records",   report.get("raw_records", 0))
    c2.metric("Clean records", report.get("clean_records", 0))
    c3.metric("Dropped (short desc.)", report.get("dropped_short_description", 0))
    c4.metric("Dropped (duplicate id)", report.get("dropped_duplicate_ids", 0))

    f1, f2, f3, f4 = st.columns(4)
    f1.metric("Unknown category", report.get("flagged_unknown_category", 0))
    f2.metric("Unknown provider", report.get("flagged_unknown_provider", 0))
    f3.metric("Provider/description conflict", report.get("flagged_provider_conflict", 0))
    f4.metric("Confirmed-bad CLI example", report.get("flagged_bad_cli_example", 0))

    total_dropped = report.get("dropped_short_description", 0) + report.get("dropped_duplicate_ids", 0)
    total_flagged = (report.get("flagged_unknown_category", 0)
                      + report.get("flagged_unknown_provider", 0)
                      + report.get("flagged_provider_conflict", 0)
                      + report.get("flagged_bad_cli_example", 0))
    if total_dropped:
        st.warning("{} record(s) dropped during cleaning (empty/too-short description or "
                   "duplicate id) - not scored, not mapped.".format(total_dropped))
    if total_flagged:
        st.info("{} flag(s) raised across the surviving records - flagged records are NOT "
               "dropped, they're routed through normally but marked for extra review in "
               "the HITL step.".format(total_flagged))
    if not total_dropped and not total_flagged:
        st.success("No data-quality issues found.")


# SIDEBAR HEADER
with st.sidebar:
    st.title("Cloud Sentinel")
    st.caption("Remediation Engine v1.0")
    st.divider()

# HEADER + TRACKER
st.title("Cloud Sentinel Remediation Engine")
st.caption("Systematic cloud security analysis and CLI remediation script generation")

done_flags = [
    st.session_state.df is not None,
    st.session_state.scored_df is not None,
    st.session_state.reviewed_confirmed,
    st.session_state.remediation_confirmed,
    st.session_state.eval_report is not None,
]
render_step_tracker(st.session_state.current_step, done_flags)

step = st.session_state.current_step


def finish_sidebar():
    """Status + reset block, rendered after the step actions."""
    with st.sidebar:
        st.caption("HITL: Human-in-the-Loop ENABLED")
        st.caption("No live cloud changes are made.")
        if st.session_state.data_source:
            st.caption("Source: " + st.session_state.data_source)
        st.divider()
        if st.button("Start Over (reset pipeline)", use_container_width=True,
                     key="reset_sb"):
            reset_pipeline()
            st.rerun()


# STEP 0 - LOAD DATA
if step == 0:
    locked = done_flags[0] and not is_unlocked(0)

    # The local JSONL dataset file is the only supported source; there is
    # no upload path. See modules/data_loader.py for the ingestion policy.
    def _finish_load(df_clean, label, report):
        st.session_state.df                    = df_clean
        st.session_state.data_source           = label
        st.session_state.cleaning_report       = report
        st.session_state.scored_df             = None
        st.session_state.approved              = set()
        st.session_state.eval_report           = None
        st.session_state.reviewed_confirmed    = False
        st.session_state.remediation_confirmed = False
        st.session_state.selected_vuln_id      = None
        goto(1)

    # None means every in-scope (AWS/Azure/GCP) record in the dataset. The
    # template library is keyed by category, provider and service rather than
    # by record, so it covers the full in-scope set, not a fixed sample.
    limit = None

    def _load_local():
        with st.spinner("Loading dataset from {}...".format(DEFAULT_DATASET_PATH.name)):
            df_raw, label, report = load_and_clean_from_local_jsonl(limit=limit)
        _finish_load(df_raw, label, report)

    nav_actions  = []
    step_actions = []
    if not locked:
        step_actions.append(act("Load & Clean from Dataset File", "s0_fetch", _load_local,
                                type="primary"))
    if done_flags[0]:
        nav_actions.append(act("Continue to: Score & Map →", "s0_next",
                               make_goto(1), type="primary"))
        if locked:
            step_actions.append(act("Reload data", "s0_unlock", make_unlock(0)))
        else:
            step_actions.append(act("Cancel — keep current data", "s0_lock", make_lock(0)))

    render_sidebar_actions(nav_actions)
    finish_sidebar()

    st.subheader("Step 1 — Load Data")
    st.caption("Source: local dataset file ({}) only. "
               "Every load runs through automatic cleaning before it reaches scoring.".format(
                   DEFAULT_DATASET_PATH.name))
    render_step_actions(step_actions)

    report = st.session_state.cleaning_report

    if locked:
        st.markdown(
            '<div class="done-banner">Data loaded &amp; cleaned — <b>{}</b> records<br>'
            'Source: {}</div>'.format(len(st.session_state.df), st.session_state.data_source),
            unsafe_allow_html=True)
        if report:
            _render_cleaning_report(report)
        with st.expander("Preview loaded data"):
            st.dataframe(st.session_state.df.head(15),
                         use_container_width=True, hide_index=True)
        flagged = get_flagged_records(st.session_state.df)
        if len(flagged):
            with st.expander("Flagged records requiring extra review ({})".format(len(flagged))):
                cols = [c for c in ["id", "category", "cloud_provider",
                                     "unknown_category_flag", "unknown_provider_flag",
                                     "provider_conflict", "cli_example_flag"]
                        if c in flagged.columns]
                st.dataframe(flagged[cols], use_container_width=True, hide_index=True)
        st.stop()

    st.caption("Loads all in-scope records (AWS / Azure / GCP only). "
           "Use **Load & Clean from Dataset File** in the action bar above or the sidebar.")

    if report:
        _render_cleaning_report(report)

    if done_flags[0]:
        st.caption("Loading new data will reset scoring, remediation and evaluation results.")

    st.stop()


# Guard: data must exist
if st.session_state.df is None:
    render_sidebar_actions([act("← Back to: Load Data", "guard0", make_goto(0),
                                type="primary")])
    finish_sidebar()
    st.warning("No data loaded yet.")
    st.stop()


# STEP 1 - SCORE & MAP (CVSS v4.0)
if step == 1:
    locked = done_flags[1] and not is_unlocked(1)

    def _run_engine():
        with st.spinner("Scoring with CVSS v4.0..."):
            scored = score_dataframe(st.session_state.df)
        with st.spinner("Mapping to remediation templates..."):
            mapped = process_dataframe(scored)
        st.session_state.templates             = _load_templates()
        st.session_state.scored_df             = mapped
        st.session_state.approved              = set()
        st.session_state.eval_report           = None
        st.session_state.reviewed_confirmed    = False
        st.session_state.remediation_confirmed = False
        st.session_state.selected_vuln_id      = None
        goto(2)

    nav_actions  = [act("← Back to: Load Data", "s1_back", make_goto(0))]
    step_actions = []
    if locked:
        nav_actions.append(act("Continue to: Review & Remediate (HITL) →", "s1_next",
                               make_goto(2), type="primary"))
        step_actions.append(act("Re-run the engine", "s1_unlock", make_unlock(1)))
    else:
        step_actions.append(act("Run Scoring & Mapping Engine", "s1_run",
                                _run_engine, type="primary"))
        if done_flags[1]:
            step_actions.append(act("Cancel — keep current results", "s1_lock",
                                    make_lock(1)))

    render_sidebar_actions(nav_actions)
    finish_sidebar()

    st.subheader("Step 2 — Score & Map (CVSS v4.0)")
    render_step_actions(step_actions)

    if locked:
        sdf = st.session_state.scored_df
        matched = int(sdf["script_matched"].sum()) if "script_matched" in sdf.columns else 0
        st.markdown(
            '<div class="done-banner">Scoring &amp; mapping complete — <b>{}</b> records '
            'scored with CVSS v4.0, <b>{}</b> matched to a validated remediation '
            'template.</div>'.format(len(sdf), matched), unsafe_allow_html=True)

        health = templates_health_check()
        if not health["templates_json_found"]:
            st.error(
                "Resource-specific template library NOT loaded from {} — every "
                "script above is coming from the {} generic per-category "
                "fallback templates only, not the resource-specific ones "
                "(S3, RDS, AKS, etc.). Fix the file path and re-run this "
                "step.".format(health["templates_json_path"], health["builtin_template_count"])
            )
        else:
            st.caption(
                "Template library loaded: {} generic + {} resource-specific "
                "= {} total templates active.".format(
                    health["builtin_template_count"],
                    health["resource_specific_count"],
                    health["total_template_count"])
            )

        with st.expander("Preview scored data"):
            st.dataframe(sdf[["id", "category", "cloud_provider", "severity",
                              "cvss_vector", "cvss_adjusted"]].head(15),
                         use_container_width=True, hide_index=True)
        st.stop()

    st.caption("Loaded {} records from: {}".format(
        len(st.session_state.df), st.session_state.data_source))
    with st.expander("Raw dataset preview"):
        st.dataframe(st.session_state.df.head(20),
                     use_container_width=True, hide_index=True)
    if done_flags[1]:
        st.caption("Re-running will reset remediation approvals and the evaluation report.")
    st.stop()


# Guard: scoring must be complete
if st.session_state.scored_df is None:
    render_sidebar_actions([act("← Back to: Score & Map", "guard1", make_goto(1),
                                type="primary")])
    finish_sidebar()
    st.warning("Run the scoring & mapping engine first.")
    st.stop()

df    = st.session_state.scored_df
tmpls = st.session_state.templates or _load_templates()


# STEP 2 - REVIEW & REMEDIATE (HITL)   [dashboard + threat registry]
if step == 2:
    locked = done_flags[2] and not is_unlocked(2)

    def _confirm_review():
        st.session_state.reviewed_confirmed = True
        goto(3)

    nav_actions  = [act("← Back to: Score & Map", "s2_back", make_goto(1))]
    step_actions = []
    if locked:
        nav_actions.append(act("Continue to: Generate Remediation Script →", "s2_next",
                               make_goto(3), type="primary"))
        step_actions.append(act("Review threats again", "s2_unlock", make_unlock(2)))
    else:
        nav_actions.append(act("Continue to: Generate Remediation Script →", "s2_next",
                               _confirm_review, type="primary"))

    render_sidebar_actions(nav_actions)
    finish_sidebar()

    st.subheader("Step 3 — Review & Remediate (HITL)")
    render_step_actions(step_actions)

    if locked:
        st.markdown(
            '<div class="done-banner">Threat landscape reviewed — <b>{}</b> vulnerabilities '
            'scored and ranked. Continue to select a target and generate its '
            'remediation script.</div>'.format(len(df)), unsafe_allow_html=True)
        st.stop()

    st.info(
        "[!] HUMAN-IN-THE-LOOP: this system only analyses and prepares remediation "
        "for human review. Nothing is executed and no live changes are made to any "
        "cloud environment."
    )

    if "provider_conflict" in df.columns and df["provider_conflict"].any():
        n_conflict = int(df["provider_conflict"].sum())
        st.warning(
            "[!] {} record(s) have a description that names a DIFFERENT cloud "
            "provider than their labeled 'cloud_provider' field (a data-quality "
            "issue in the source dataset). The remediation script is generated "
            "for the LABELED provider — check the **Data Quality** tab before "
            "approving any of these.".format(n_conflict)
        )

    sub_dash, sub_registry, sub_conflicts = st.tabs(
        ["Dashboard", "Threat Registry", "Data Quality"])

    with sub_dash:
        st.caption("Analysed from: " + (st.session_state.data_source or "unknown source"))

        total_debt = compute_security_debt(df)
        breakdown  = get_severity_breakdown(df)
        approved   = st.session_state.approved
        rem_debt   = df[df["id"].isin(approved)]["cvss_adjusted"].sum() if approved else 0.0

        c1, c2, c3, c4, c5, c6 = st.columns(6)
        c1.metric("Total Vulnerabilities", len(df))
        c2.metric("Critical",  breakdown.get("CRITICAL", 0))
        c3.metric("High",      breakdown.get("HIGH",     0))
        c4.metric("Medium",    breakdown.get("MEDIUM",   0))
        c5.metric("Security Debt", "{:.1f}".format(total_debt))
        c6.metric("Debt Reduced",  "{:.1f}".format(rem_debt),
                  delta="-{:.1f}".format(rem_debt) if rem_debt else None)

        st.divider()
        col_left, col_right = st.columns(2)
        with col_left:
            st.markdown("**Vulnerabilities by Category**")
            cat_df = get_category_breakdown(df)
            st.bar_chart(cat_df.set_index("category")["count"], use_container_width=True)
            st.markdown("**Security Debt by Category (CVSS pts)**")
            st.bar_chart(cat_df.set_index("category")["total_cvss"], use_container_width=True)
        with col_right:
            st.markdown("**Vulnerabilities by Cloud Provider**")
            prov_df = get_provider_breakdown(df)
            st.bar_chart(prov_df.set_index("cloud_provider")["count"], use_container_width=True)
            st.markdown("**Security Debt by Cloud Provider**")
            st.bar_chart(prov_df.set_index("cloud_provider")["total_cvss"], use_container_width=True)

        st.divider()
        st.markdown("**Severity Distribution**")
        sev_counts = df["severity"].value_counts().reindex(
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"], fill_value=0).reset_index()
        sev_counts.columns = ["Severity", "Count"]
        st.bar_chart(sev_counts.set_index("Severity"), use_container_width=True)

        st.divider()
        st.markdown("**Top 10 Highest Risk Vulnerabilities**")
        top10 = df.head(10)[["priority_rank", "id", "cloud_provider", "category",
                             "service", "severity", "cvss_adjusted", "description"]]
        st.dataframe(top10.rename(columns={"priority_rank": "Rank",
                                           "cloud_provider": "Provider",
                                           "cvss_adjusted": "CVSS Score"}),
                     use_container_width=True, hide_index=True)

    with sub_registry:
        st.markdown("**Threat Registry — {} vulnerabilities**".format(len(df)))
        fc1, fc2, fc3, fc4 = st.columns(4)
        with fc1:
            sev_f = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                                   default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        with fc2:
            prov_f = st.multiselect("Cloud Provider",
                                    sorted(df["cloud_provider"].unique().tolist()),
                                    default=sorted(df["cloud_provider"].unique().tolist()))
        with fc3:
            cat_f = st.multiselect("Category", sorted(df["category"].unique().tolist()),
                                   default=sorted(df["category"].unique().tolist()))
        with fc4:
            search = st.text_input("Search description", "")

        filtered = df[df["severity"].isin(sev_f)
                      & df["cloud_provider"].isin(prov_f)
                      & df["category"].isin(cat_f)]
        if search:
            filtered = filtered[filtered["description"].str.contains(search, case=False, na=False)]
        filtered = filtered.sort_values("cvss_adjusted", ascending=False)

        cols = ["priority_rank", "id", "cloud_provider", "category", "service",
                "severity", "cvss_adjusted", "description"]
        cols = [c for c in cols if c in filtered.columns]
        st.dataframe(filtered[cols].rename(columns={"priority_rank": "Rank",
                                                    "cloud_provider": "Provider",
                                                    "cvss_adjusted": "CVSS"}),
                     use_container_width=True, hide_index=True, height=460)
        st.caption("Showing {} of {} records".format(len(filtered), len(df)))

    with sub_conflicts:
        if "provider_conflict" not in df.columns or not df["provider_conflict"].any():
            st.success("No provider/description conflicts detected in this dataset.")
        else:
            conflicts = df[df["provider_conflict"]]
            st.markdown(
                "**{} record(s) with a provider/description mismatch**".format(len(conflicts)))
            st.caption(
                "The 'cloud_provider' column and the free-text description disagree on "
                "which cloud the vulnerability belongs to. The remediation engine trusts "
                "the labeled 'cloud_provider' column (never guesses from prose), so the "
                "generated script targets the label shown — verify that's correct before "
                "approving."
            )
            show_cols = ["id", "cloud_provider", "category", "severity",
                        "provider_conflict_note", "description"]
            show_cols = [c for c in show_cols if c in conflicts.columns]
            st.dataframe(
                conflicts[show_cols].rename(columns={
                    "cloud_provider": "Labeled Provider",
                    "provider_conflict_note": "Conflict",
                }),
                use_container_width=True, hide_index=True, height=460)

    st.stop()


# STEP 3 - GENERATE REMEDIATION SCRIPT
# Filter, select, generate, approve, and download the script on one page.
if step == 3:
    locked = done_flags[3] and not is_unlocked(3)

    # Locked summary view
    if locked:
        approved_df = df[df["id"].isin(st.session_state.approved)]
        nav_actions = [act("← Back to: Review & Remediate (HITL)", "s3_back",
                           make_goto(2)),
                       act("Continue to: Run Evaluation →", "s3_next", make_goto(4),
                           type="primary")]
        step_actions = [act("Generate another script", "s3_unlock", make_unlock(3))]
        if not approved_df.empty:
            batch = "\n\n".join(generate_script(r, tmpls)["script_text"]
                                for _, r in approved_df.iterrows())
            step_actions.append(dl("Download all approved (batch.sh)", "s3_batch_locked",
                                   batch, "cloud_sentinel_batch.sh"))

        render_sidebar_actions(nav_actions)
        finish_sidebar()

        st.subheader("Step 4 — Generate Remediation Script")
        render_step_actions(step_actions)
        st.markdown(
            '<div class="done-banner">Remediation stage complete — <b>{}</b> script(s) '
            'approved and ready to download.</div>'.format(len(st.session_state.approved)),
            unsafe_allow_html=True)
        if not approved_df.empty:
            st.dataframe(approved_df[["id", "cloud_provider", "category",
                                      "severity", "cvss_adjusted"]],
                         use_container_width=True, hide_index=True)
        st.stop()

    # Open view: filters + selection + script SIDE BY SIDE
    st.subheader("Step 4 — Generate Remediation Script")

    # Action bar renders into this container, so it sits ABOVE both panes even
    # though its contents depend on the selection made below.
    ph_actions = st.container()

    # Left pane = filter/select/details, right pane = generated script.
    # Both are laid out before any long content so nothing needs scrolling.
    pane_select, pane_script = st.columns([1, 2], gap="large")

    with pane_select:
        st.markdown("##### 1. Filter and select")
        r_prov = st.selectbox("Filter by Provider",
                              ["All"] + sorted(df["cloud_provider"].unique().tolist()),
                              key="f_prov")
        r_sev = st.selectbox("Filter by Severity",
                             ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="f_sev")
        r_cat = st.selectbox("Filter by Category",
                             ["All"] + sorted(df["category"].unique().tolist()),
                             key="f_cat")

    rem_pool = df.copy()
    if r_prov != "All":
        rem_pool = rem_pool[rem_pool["cloud_provider"] == r_prov]
    if r_sev != "All":
        rem_pool = rem_pool[rem_pool["severity"] == r_sev]
    if r_cat != "All":
        rem_pool = rem_pool[rem_pool["category"] == r_cat]
    rem_pool = rem_pool.sort_values("cvss_adjusted", ascending=False)

    if rem_pool.empty:
        acts = [act("← Back to: Review & Remediate (HITL)", "s3_back", make_goto(2)),
                act("Continue to: Run Evaluation →", "s3_next_empty",
                    make_goto(4), type="primary")]
        render_sidebar_actions(acts)
        finish_sidebar()
        with pane_select:
            st.warning("No vulnerabilities match the selected filters.")
        st.stop()

    options = {
        "[{}] {} | {} | {} | CVSS {}".format(
            row["severity"], row["id"], row["cloud_provider"],
            row["category"], row["cvss_adjusted"]): row["id"]
        for _, row in rem_pool.iterrows()
    }
    labels_list = list(options.keys())

    default_idx = 0
    if st.session_state.selected_vuln_id in options.values():
        for i, lab in enumerate(labels_list):
            if options[lab] == st.session_state.selected_vuln_id:
                default_idx = i
                break

    with pane_select:
        selected_label = st.selectbox(
            "Vulnerability ({} match the filters)".format(len(rem_pool)),
            labels_list, index=default_idx, key="vuln_select")

    sel_id = options[selected_label]
    st.session_state.selected_vuln_id = sel_id
    vuln   = df[df["id"] == sel_id].iloc[0]
    result = generate_script(vuln, tmpls)

    vuln_id     = str(vuln["id"])
    is_approved = vuln_id in st.session_state.approved

    # Checklist state is read from session_state so the Approve button in the
    # top bar / sidebar can be enabled on the same run the boxes are ticked.
    chk_keys = ["chk1_{}".format(vuln_id), "chk2_{}".format(vuln_id),
                "chk3_{}".format(vuln_id), "chk4_{}".format(vuln_id)]
    all_ticked = all(st.session_state.get(k, False) for k in chk_keys)

    def _approve():
        st.session_state.approved.add(vuln_id)
        st.rerun()

    def _revoke():
        st.session_state.approved.discard(vuln_id)
        st.rerun()

    def _confirm_remediation():
        st.session_state.remediation_confirmed = True
        goto(4)

    nav_actions  = [act("← Back to: Review & Remediate (HITL)", "s3_back", make_goto(2)),
                    act("Continue to: Run Evaluation →", "s3_next",
                        _confirm_remediation,
                        type="primary" if is_approved else "secondary")]
    step_actions = []
    if is_approved:
        step_actions.append(dl("Download remediate_{}.sh".format(vuln_id), "s3_dl",
                               result["script_text"], "remediate_{}.sh".format(vuln_id)))
        step_actions.append(act("Revoke approval", "s3_revoke", _revoke))
    else:
        step_actions.append(act("Approve Script", "s3_approve", _approve,
                                type="primary", disabled=not all_ticked))
    if st.session_state.approved:
        batch = "\n\n".join(
            generate_script(r, tmpls)["script_text"]
            for _, r in df[df["id"].isin(st.session_state.approved)].iterrows())
        step_actions.append(dl("Download all approved ({})".format(len(st.session_state.approved)),
                               "s3_batch", batch, "cloud_sentinel_batch.sh"))

    with ph_actions:
        render_step_actions(step_actions)
    render_sidebar_actions(nav_actions)
    finish_sidebar()

    # LEFT PANE: vulnerability detail + HITL checklist
    with pane_select:
        st.markdown("**Vulnerability Details**")
        sev = vuln["severity"]
        if sev == "CRITICAL":
            st.error("CRITICAL | CVSS {}".format(vuln["cvss_adjusted"]))
        elif sev == "HIGH":
            st.warning("HIGH | CVSS {}".format(vuln["cvss_adjusted"]))
        else:
            st.info("{} | CVSS {}".format(sev, vuln["cvss_adjusted"]))
        st.markdown("**ID:** {}  \n**Provider:** {}  \n**Category:** {}  \n**Service:** {}".format(
            vuln["id"], vuln["cloud_provider"], vuln["category"], vuln.get("service", "N/A")))

        if bool(vuln.get("provider_conflict", False)):
            st.warning(
                "[!] Data-quality conflict: {} The script below is generated for the "
                "LABELED provider ('{}'), not whatever the description implies. "
                "Verify the correct provider before approving.".format(
                    vuln.get("provider_conflict_note", ""), vuln["cloud_provider"])
            )
        if bool(vuln.get("unknown_category_flag", False)):
            st.warning("[!] Category '{}' isn't in the known taxonomy - the script below "
                      "used the closest generic fallback template.".format(vuln.get("category", "")))
        if bool(vuln.get("unknown_provider_flag", False)):
            st.warning("[!] Cloud provider '{}' wasn't recognised - the script below "
                      "used a generic scaffold rather than a provider-specific CLI.".format(
                          vuln.get("cloud_provider", "")))
        if bool(vuln.get("cli_example_flag", False)):
            st.error("[!] Confirmed data-quality issue: {}".format(
                vuln.get("cli_example_flag_note", "")))

        with st.expander("Description / CVSS vector / vulnerable config"):
            st.write(vuln["description"])
            if "cvss_vector" in vuln:
                st.markdown("**CVSS v4.0 Vector**")
                st.code(str(vuln["cvss_vector"]), language="text")
            if "vulnerable_code" in vuln and str(vuln.get("vulnerable_code", "")) not in ["", "nan"]:
                st.markdown("**Vulnerable Code/Config**")
                st.code(str(vuln["vulnerable_code"]), language="yaml")

        st.divider()
        if is_approved:
            st.success("Script approved — use **Download remediate_{}.sh** "
                       "in the sidebar.".format(vuln_id))
        else:
            st.markdown("##### 3. HITL Review Checklist")
            st.caption("Tick all four, then use **Approve Script** in the sidebar.")
            st.checkbox("I have read every command and understand its effect",
                        key=chk_keys[0])
            st.checkbox("I have replaced all {{PLACEHOLDER}} values with real values",
                        key=chk_keys[1])
            st.checkbox("I have tested this in a non-production environment",
                        key=chk_keys[2])
            st.checkbox("I take responsibility for executing this script",
                        key=chk_keys[3])

    # RIGHT PANE: the generated script
    with pane_script:
        st.markdown("##### 2. Generated remediation script")
        st.markdown("**{}**".format(result["title"]))
        st.caption(result["description"])
        if result["matched"]:
            st.success("Validated template matched (key: {})".format(result["matched_key"]))
        else:
            st.warning("No exact template — scaffold generated. Complete manually.")

        # Fixed-height scroll box: a long script cannot push the checklist
        # or the rest of the page out of view.
        try:
            box = st.container(height=560, border=True)
        except TypeError:      # Streamlit < 1.31 has no height/border args
            box = st.container()
        with box:
            st.code(result["script_text"], language="bash")

    if st.session_state.approved:
        st.divider()
        st.markdown("**Approved Scripts ({})**".format(len(st.session_state.approved)))
        st.dataframe(
            df[df["id"].isin(st.session_state.approved)][
                ["id", "cloud_provider", "category", "severity", "cvss_adjusted"]],
            use_container_width=True, hide_index=True)

    st.stop()


# STEP 4 - RUN EVALUATION
if step == 4:
    def _run_eval():
        with st.spinner("Running evaluation..."):
            st.session_state.eval_report = run_full_evaluation(df)
        st.rerun()

    def _clear_eval():
        st.session_state.eval_report = None
        st.rerun()

    nav_actions  = [act("← Back to: Generate Remediation Script", "s4_back",
                        make_goto(3))]
    step_actions = []
    if done_flags[4]:
        step_actions.append(act("Re-run evaluation", "s4_rerun", _clear_eval))
    else:
        step_actions.append(act("Run Full Evaluation Suite", "s4_run", _run_eval,
                                type="primary"))

    render_sidebar_actions(nav_actions)
    finish_sidebar()

    st.subheader("Step 5 — Run Evaluation")
    render_step_actions(step_actions)
    st.caption("Structural script audit (target >= 90%) + time efficiency vs manual research")

    if not done_flags[4]:
        st.info("Use **Run Full Evaluation Suite** in the action bar above or the sidebar.")
        st.stop()

    report = st.session_state.eval_report
    sa     = report["syntax_audit"]
    te     = report["time_efficiency"]
    debt   = compute_security_debt_reduction(df, list(st.session_state.approved))

    st.markdown('<div class="done-banner">Evaluation complete — pipeline finished.</div>',
                unsafe_allow_html=True)

    st.markdown("### 5.1 — Structural Script Audit")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Scripts", sa["total_scripts"])
    m2.metric("Passed",        sa["passed"])
    m3.metric("Failed",        sa["failed"])
    m4.metric("Structural Pass Rate", "{}%".format(sa["accuracy_pct"]))
    if sa["target_met"]:
        st.success("Structural pass rate {}% >= 90% target".format(sa["accuracy_pct"]))
    else:
        st.error("Structural pass rate {}% is below the 90% target".format(sa["accuracy_pct"]))

    st.caption(sa["caveat"])

    c1, c2, c3 = st.columns(3)
    c1.metric("Template Match Rate", "{}%".format(sa["template_match_pct"]),
              help="Records that hit a real template rather than a manual-review scaffold.")
    c2.metric("Fallback Scaffolds", sa["fallback_scaffolds"],
              help="Comment-only scaffolds; these now count as FAILED, not passed.")
    c3.metric("Signatures Doc-Checked", "{}%".format(sa["doc_verified_pct"]),
              help="Share of distinct command signatures used here that a human has "
                   "checked against official provider docs. Run "
                   "tools/audit_templates.py separately for the full breakdown.")

    if sa["failed_details"]:
        with st.expander("Failed scripts ({})".format(sa["failed"])):
            st.json(sa["failed_details"][:50])
    if sa["warning_samples"]:
        with st.expander("Warnings — placeholders awaiting human input "
                         "({} scripts)".format(sa["scripts_with_warnings"])):
            st.caption("Unfilled {{PLACEHOLDER}} tokens are required by the review "
                       "workflow and are warnings, not failures.")
            st.json(sa["warning_samples"])

    st.markdown("### 5.2 — Time Efficiency")
    t1, t2, t3, t4 = st.columns(4)
    t1.metric("Engine Time",     "{:.3f}s".format(te["engine_time_seconds"]))
    t2.metric("Manual Estimate", "{:.0f} min".format(te["manual_estimated_minutes"]))
    t3.metric("Net Time Saved",  "{:.0f} min".format(te["net_time_saved_minutes"]))
    t4.metric("Net Reduction",   te["net_reduction_display"],
              help="Includes the mandatory human review this tool is gated on.")

    with st.expander("Machine-time-only figures (why these are not the headline)"):
        r1, r2, r3 = st.columns(3)
        r1.metric("Raw Reduction", te["raw_reduction_display"])
        r2.metric("Speed-up", "{:,.0f}x".format(te["speedup_factor"]))
        r3.metric("HITL Review Cost", "{:.0f} min".format(te["hitl_total_minutes"]))
        st.caption(te["caveat"])

    st.info("Engine generated {} scripts in {:.3f}s. Against an estimated {:.0f} min of "
            "manual research, and adding {:.0f} min of required human review, the net "
            "saving is {:.0f} min ({}).".format(
                te["scripts_generated"], te["engine_time_seconds"],
                te["manual_estimated_minutes"], te["hitl_total_minutes"],
                te["net_time_saved_minutes"], te["net_reduction_display"]))

    st.markdown("### Security Debt Reduction")
    d1, d2, d3, d4 = st.columns(4)
    d1.metric("Initial Debt",  debt["initial_debt"])
    d2.metric("Remediated",    debt["remediated_debt"])
    d3.metric("Remaining",     debt["remaining_debt"])
    d4.metric("Reduction",     "{}%".format(debt["reduction_pct"]))
    st.caption("Based on {} of {} records with a real matched AWS/Azure/GCP command. "
               "{}".format(debt["in_scope_records"], debt["total_records"], debt["note"]))

    st.markdown("### CVSS v4.0 Verification")
    verify = verify_scoring_logic(df)
    if verify["passed"]:
        st.success("All {} CVSS v4.0 scores verified — no errors".format(verify["total_records"]))
    else:
        st.error("{} scoring issues found".format(verify["issues_found"]))
    st.json({"severity_distribution": verify["severity_counts"],
             "total_security_debt":   verify["security_debt"]})
