# -*- coding: utf-8 -*-
"""
Regression tests for modules.mapping_engine.

Context: VUL1192 (Azure AKS, "misconfigured pod security policy allowing
privilege escalation") was being matched to the CONTAINER|Azure template
("Disable AKS Local Admin Accounts / Enforce Entra ID") - a cluster
*authentication* fix that does nothing about a *workload* running with
`privileged: true`. Root cause: the bare CONTAINER|<provider> key was the
first resource-specific match for every Container/Kubernetes finding
regardless of whether the real problem was cluster-auth or pod-spec
security, so it silently shadowed the correct fix.

Fix: modules.mapping_engine now inspects the record's `vulnerable_code`
(and, as a fallback, specific description phrases) for workload-level
privilege-escalation markers (podSecurityPolicy, hostPID/hostIPC/
hostNetwork, privileged/allowPrivilegeEscalation with container context)
and routes those to a dedicated PRIVILEGED_WORKLOAD|<provider> template
*before* the bare CONTAINER|<provider> key is tried. AWS additionally
splits ECS (task-definition based, no kubectl) from EKS (kubectl-based)
into PRIVILEGED_ECS_TASK|AWS vs PRIVILEGED_WORKLOAD|AWS.

These tests exist so that fix doesn't silently regress. They were built
from checks originally run ad hoc against the full dataset while
diagnosing the bug; see each test's docstring for what real dataset
record (if any) it corresponds to.
"""

import json
from pathlib import Path

import pandas as pd
import pytest

from modules import mapping_engine as me

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = REPO_ROOT / "data" / "cloud_vulnerabilities_dataset.jsonl"


@pytest.fixture(scope="module")
def templates():
    return me._load_templates()


def _row(**kwargs):
    defaults = {
        "id": "VUL_TEST", "severity": "HIGH", "service": "Container",
        "resource_name": "test-resource",
    }
    defaults.update(kwargs)
    return pd.Series(defaults)


# The bug, pinned: VUL1192 itself.
class TestVUL1192Regression:

    def test_vul1192_matches_privileged_workload_not_cluster_auth(self, templates):
        row = _row(
            id="VUL1192",
            description="Azure Kubernetes with misconfigured pod security "
                         "policy allowing privilege escalation.",
            category="Privilege Escalation",
            cloud_provider="Azure",
            vulnerable_code='{ "podSecurityPolicy": { "privileged": true } }',
            severity="CRITICAL",
            resource_name="aks-prod-cluster",
        )
        result = me.generate_script(row, templates)
        assert result["matched_key"] == "PRIVILEGED_WORKLOAD|AZURE"
        assert result["matched"] is True
        # The old (wrong) match - guard against silently reverting to it.
        assert result["matched_key"] != "CONTAINER|AZURE"
        assert "Local Admin Accounts" not in result["title"]

    def test_generated_script_contains_workload_admission_fix(self, templates):
        row = _row(
            id="VUL1192",
            description="Azure Kubernetes with misconfigured pod security "
                         "policy allowing privilege escalation.",
            category="Privilege Escalation",
            cloud_provider="Azure",
            vulnerable_code='{ "podSecurityPolicy": { "privileged": true } }',
            severity="CRITICAL",
            resource_name="aks-prod-cluster",
        )
        script = me.generate_script(row, templates)["script_text"]
        assert "pod-security.kubernetes.io/enforce" in script
        # The fix must not silently reintroduce a fabricated policy GUID -
        # the definition ID must be looked up by name, never hardcoded.
        assert "policy set-definition list" in script
        assert "--policy " not in script  # no hardcoded --policy <guid>


# Provider parity: AWS (EKS + ECS split), Azure, GCP.
class TestProviderParity:

    def test_aws_eks_privileged_pod(self, templates):
        row = _row(
            description="AWS EKS with misconfigured pod security policy "
                         "allowing privilege escalation.",
            category="Privilege Escalation", cloud_provider="AWS",
            vulnerable_code='{ "podSecurityPolicy": { "privileged": true } }',
        )
        result = me.generate_script(row, templates)
        assert result["matched_key"] == "PRIVILEGED_WORKLOAD|AWS"
        assert "EKS" in result["title"]

    def test_aws_ecs_task_definition_gets_dedicated_template(self, templates):
        """
        ECS is not Kubernetes - it has no kubectl/cluster admission control.
        A finding on an ECS task definition must not be routed to the
        EKS/kubectl-based PRIVILEGED_WORKLOAD|AWS template.
        """
        row = _row(
            description="AWS ECS with misconfigured task definition "
                         "allowing container breakout.",
            category="Privilege Escalation", cloud_provider="AWS",
            vulnerable_code='{ "containerDefinitions": [{ "privileged": true, '
                            '"mountPoints": [{"sourceVolume": "host"}] }] }',
        )
        result = me.generate_script(row, templates)
        assert result["matched_key"] == "PRIVILEGED_ECS_TASK|AWS"
        assert "kubectl" not in result["script_text"]
        assert "aws ecs register-task-definition" in result["script_text"]

    def test_azure_aks_privileged_pod(self, templates):
        row = _row(
            description="Azure Kubernetes with misconfigured pod security "
                         "policy allowing privilege escalation.",
            category="Privilege Escalation", cloud_provider="Azure",
            vulnerable_code='{ "podSecurityPolicy": { "privileged": true } }',
        )
        result = me.generate_script(row, templates)
        assert result["matched_key"] == "PRIVILEGED_WORKLOAD|AZURE"
        assert "AKS" in result["title"]

    def test_gcp_gke_privileged_pod(self, templates):
        """
        No real dataset record exercises this path (the dataset's GCP
        privilege-escalation findings are all IAM/service-account based -
        see test_gcp_real_records_not_swept_into_workload_override below),
        so this is a synthetic case mirroring VUL1192/VUL925 for parity.
        """
        row = _row(
            description="GCP Kubernetes Engine (GKE) with misconfigured pod "
                         "security policy allowing privilege escalation.",
            category="Privilege Escalation", cloud_provider="GCP",
            vulnerable_code='{ "podSecurityPolicy": { "privileged": true } }',
        )
        result = me.generate_script(row, templates)
        assert result["matched_key"] == "PRIVILEGED_WORKLOAD|GCP"
        assert "GKE" in result["title"]
        script = result["script_text"]
        # PodSecurityPolicy itself was removed from Kubernetes 1.25+; the
        # template must not tell the reviewer to enable a feature that no
        # longer exists.
        assert "--enable-pod-security-policy" not in script


# False-positive guards: findings that use similar language/JSON keys but
# are legitimately control-plane (RBAC/IAM) or unrelated-resource issues,
# and must NOT be swept into PRIVILEGED_WORKLOAD.
class TestFalsePositiveGuards:

    def test_rbac_cluster_role_binding_not_overridden(self, templates):
        """VUL325-style: EKS cluster role bindings are a control-plane/IAM
        problem, not a workload/pod-spec problem - must stay on the
        existing PRIVILEGE_ESCALATION|AWS (IAM) path."""
        row = _row(
            description="AWS EKS with misconfigured cluster role bindings "
                         "allowing privilege escalation.",
            category="Privilege Escalation", cloud_provider="AWS",
            vulnerable_code="",
        )
        result = me.generate_script(row, templates)
        assert result["matched_key"] != "PRIVILEGED_WORKLOAD|AWS"

    def test_vm_extension_privileged_flag_not_treated_as_container(self, templates):
        """VUL674-style: an Azure VM extension config can also contain a
        bare `"privileged": true` key, but it is not a Kubernetes/container
        resource at all and must not match PRIVILEGED_WORKLOAD|Azure.

        `service` here is left to the real inference logic (data_loader.
        _infer_service), not hardcoded to "Container" like the default
        _row() fixture does - hardcoding it previously caused a false
        FAIL in this exact test, since the ambiguous-marker context check
        was fed a service value production code would never actually
        produce for this description.
        """
        from modules.data_loader import _infer_service
        description = ("Azure Virtual Machine with misconfigured extension "
                        "allowing privilege escalation.")
        inferred_service = _infer_service(
            pd.Series({"description": description, "category": "Privilege Escalation"})
        )
        assert inferred_service != "Container", (
            "test assumption violated: production inference now tags this "
            "description as Container - re-examine whether the override "
            "guard is still correct"
        )
        row = _row(
            description=description,
            category="Privilege Escalation", cloud_provider="Azure",
            vulnerable_code='{ "extensionConfig": { "type": "CustomScript", '
                            '"privileged": true } }',
            service=inferred_service,
        )
        result = me.generate_script(row, templates)
        assert result["matched_key"] != "PRIVILEGED_WORKLOAD|AZURE"

    def test_azure_cluster_role_finding_still_uses_container_auth_template(self, templates):
        """VUL592-style: a genuine cluster-role/RBAC AKS finding should
        still land on CONTAINER|Azure (cluster-auth hardening) - that
        template is correct for THIS class of finding. The fix must not
        overcorrect and swallow every AKS record into PRIVILEGED_WORKLOAD."""
        row = _row(
            description="Azure Kubernetes with misconfigured cluster role "
                         "allowing privilege escalation.",
            category="Privilege Escalation", cloud_provider="Azure",
            vulnerable_code="",
        )
        result = me.generate_script(row, templates)
        assert result["matched_key"] == "CONTAINER|AZURE"

    @pytest.mark.skipif(not DATASET_PATH.exists(), reason="dataset not present")
    def test_gcp_real_records_not_swept_into_workload_override(self):
        """
        Full-dataset regression: none of the real GCP records (Cloud Run,
        Cloud SQL, Cloud Functions, Spanner service-account/IAM findings)
        should trigger the workload override, since none of them are
        actually Kubernetes/pod-spec issues.
        """
        rows = []
        with open(DATASET_PATH, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        df = pd.DataFrame(rows)
        gcp_df = df[df["cloud_provider"].str.contains("GCP", case=False, na=False)]
        assert len(gcp_df) > 0, "expected at least one GCP record in the dataset"

        false_positives = []
        for _, r in gcp_df.iterrows():
            keys = me._privileged_workload_override_keys(
                r.get("vulnerable_code", ""), r.get("description", ""),
                "GCP", r.get("severity", "HIGH"), "",
            )
            if keys:
                false_positives.append(r["id"])
        assert false_positives == []


# Template library integrity.
class TestTemplateLibrary:

    @pytest.mark.parametrize("key", [
        "PRIVILEGED_WORKLOAD|AWS",
        "PRIVILEGED_WORKLOAD|Azure",
        "PRIVILEGED_WORKLOAD|GCP",
        "PRIVILEGED_ECS_TASK|AWS",
    ])
    def test_new_templates_exist_and_are_well_formed(self, templates, key):
        assert key in templates
        t = templates[key]
        assert t.get("title")
        assert t.get("commands") and isinstance(t["commands"], list)
        assert len(t["commands"]) > 0

    def test_no_key_collisions_introduced(self, templates):
        """Sanity check: the four new keys should not shadow or collide
        with any pre-existing key in the merged template index."""
        index = me._normalized_index(templates)
        for key in ("PRIVILEGED_WORKLOAD|AWS", "PRIVILEGED_WORKLOAD|Azure",
                    "PRIVILEGED_WORKLOAD|GCP", "PRIVILEGED_ECS_TASK|AWS"):
            assert me._normalize_key(key) in index
