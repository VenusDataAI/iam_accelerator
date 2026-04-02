"""Tests for the HTML/JSON report generator and remediation planner."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from auditors.aws_auditor import AWSAuditor
from auditors.azure_auditor import AzureAuditor
from auditors.base_auditor import (
    AuditPolicy,
    AuditResult,
    AuditRole,
    AuditUser,
    CloudProvider,
    AccessLevel,
)
from analyzers.permission_mapper import PermissionMapper
from analyzers.remediation_planner import (
    ActionType,
    Priority,
    RemediationPlanner,
)
from analyzers.risk_scorer import RiskLevel, RiskReport, RiskScore, RiskScorer
from reporters.executive_report import ExecutiveReportGenerator

SAMPLE_AWS = Path(__file__).parent.parent / "data" / "samples" / "aws_iam_sample.json"
SAMPLE_AZURE = Path(__file__).parent.parent / "data" / "samples" / "azure_rbac_sample.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_full_aws() -> tuple[AuditResult, RiskReport]:
    auditor = AWSAuditor(sample_data_path=SAMPLE_AWS)
    result = auditor.run()
    scorer = RiskScorer()
    report = scorer.score(result)
    return result, report


def _build_full_azure() -> tuple[AuditResult, RiskReport]:
    auditor = AzureAuditor(
        subscription_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        sample_data_path=SAMPLE_AZURE,
    )
    result = auditor.run()
    scorer = RiskScorer()
    report = scorer.score(result)
    return result, report


# ---------------------------------------------------------------------------
# PermissionMapper
# ---------------------------------------------------------------------------

class TestPermissionMapper:
    def test_nodes_and_edges_present(self) -> None:
        result, _ = _build_full_aws()
        mapper = PermissionMapper()
        graph = mapper.build(result)
        assert "nodes" in graph
        assert "edges" in graph
        assert len(graph["nodes"]) > 0
        assert len(graph["edges"]) > 0

    def test_user_nodes_exist(self) -> None:
        result, _ = _build_full_aws()
        mapper = PermissionMapper()
        graph = mapper.build(result)
        node_types = {n["type"] for n in graph["nodes"].values()}
        assert "user" in node_types

    def test_policy_nodes_exist(self) -> None:
        result, _ = _build_full_aws()
        mapper = PermissionMapper()
        graph = mapper.build(result)
        node_types = {n["type"] for n in graph["nodes"].values()}
        assert "policy" in node_types

    def test_serializable_to_json(self) -> None:
        result, _ = _build_full_aws()
        mapper = PermissionMapper()
        graph = mapper.build(result)
        json_str = mapper.to_json(graph)
        parsed = json.loads(json_str)
        assert "nodes" in parsed

    def test_dot_export_contains_digraph(self) -> None:
        result, _ = _build_full_aws()
        mapper = PermissionMapper()
        graph = mapper.build(result)
        dot = mapper.export_to_dot(graph)
        assert "digraph" in dot
        assert "->" in dot

    def test_dot_export_azure(self) -> None:
        result, _ = _build_full_azure()
        mapper = PermissionMapper()
        graph = mapper.build(result)
        dot = mapper.export_to_dot(graph)
        assert "digraph" in dot


# ---------------------------------------------------------------------------
# RemediationPlanner
# ---------------------------------------------------------------------------

class TestRemediationPlanner:
    def test_plan_has_actions(self) -> None:
        _, risk_report = _build_full_aws()
        planner = RemediationPlanner()
        plan = planner.plan(risk_report)
        assert plan.total_actions > 0

    def test_p1_actions_for_critical_resources(self) -> None:
        _, risk_report = _build_full_aws()
        planner = RemediationPlanner()
        plan = planner.plan(risk_report)
        assert plan.p1_count > 0

    def test_actions_sorted_by_priority(self) -> None:
        _, risk_report = _build_full_aws()
        planner = RemediationPlanner()
        plan = planner.plan(risk_report)
        priority_order = {Priority.P1: 0, Priority.P2: 1, Priority.P3: 2}
        priorities = [priority_order[a.priority] for a in plan.actions]
        assert priorities == sorted(priorities)

    def test_rotate_keys_action_present(self) -> None:
        _, risk_report = _build_full_aws()
        planner = RemediationPlanner()
        plan = planner.plan(risk_report)
        action_types = {a.action_type for a in plan.actions}
        assert ActionType.ROTATE_KEYS in action_types

    def test_enable_mfa_action_present(self) -> None:
        _, risk_report = _build_full_aws()
        planner = RemediationPlanner()
        plan = planner.plan(risk_report)
        action_types = {a.action_type for a in plan.actions}
        assert ActionType.ENABLE_MFA in action_types

    def test_cli_snippets_not_empty(self) -> None:
        _, risk_report = _build_full_aws()
        planner = RemediationPlanner()
        plan = planner.plan(risk_report)
        for action in plan.actions:
            assert action.cli_snippet.strip() != ""

    def test_action_ids_unique(self) -> None:
        _, risk_report = _build_full_aws()
        planner = RemediationPlanner()
        plan = planner.plan(risk_report)
        ids = [a.action_id for a in plan.actions]
        assert len(ids) == len(set(ids))

    def test_no_low_risk_actions(self) -> None:
        """Actions should only be generated for MEDIUM+ risk resources."""
        low_score = RiskScore(
            resource_id="low-r",
            resource_name="low-resource",
            resource_type="user",
            provider="aws",
            score=10,
            level=RiskLevel.LOW,
            factors=[],
        )
        report = RiskReport(
            provider="aws",
            scores=[low_score],
            top_risks=[low_score],
            risk_level=RiskLevel.LOW,
            total_resources=1,
        )
        planner = RemediationPlanner()
        plan = planner.plan(report)
        assert plan.total_actions == 0

    def test_azure_remediation(self) -> None:
        _, risk_report = _build_full_azure()
        planner = RemediationPlanner()
        plan = planner.plan(risk_report)
        assert plan.provider == "azure"


# ---------------------------------------------------------------------------
# ExecutiveReportGenerator — HTML content checks
# ---------------------------------------------------------------------------

class TestExecutiveReport:
    @pytest.fixture
    def aws_report_files(self, tmp_path: Path):
        result, risk_report = _build_full_aws()
        planner = RemediationPlanner()
        plan = planner.plan(risk_report)
        gen = ExecutiveReportGenerator(output_dir=tmp_path)
        html_path, json_path = gen.generate(result, risk_report, plan, base_name="test_report")
        return html_path, json_path

    def test_html_file_created(self, aws_report_files) -> None:
        html_path, _ = aws_report_files
        assert html_path.exists()
        assert html_path.stat().st_size > 0

    def test_json_file_created(self, aws_report_files) -> None:
        _, json_path = aws_report_files
        assert json_path.exists()

    def test_html_contains_executive_summary(self, aws_report_files) -> None:
        html_path, _ = aws_report_files
        content = html_path.read_text(encoding="utf-8")
        assert "Executive Summary" in content

    def test_html_contains_risk_level(self, aws_report_files) -> None:
        html_path, _ = aws_report_files
        content = html_path.read_text(encoding="utf-8")
        assert any(level in content for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))

    def test_html_contains_remediation_plan(self, aws_report_files) -> None:
        html_path, _ = aws_report_files
        content = html_path.read_text(encoding="utf-8")
        assert "Remediation Plan" in content

    def test_html_contains_top_10_table(self, aws_report_files) -> None:
        html_path, _ = aws_report_files
        content = html_path.read_text(encoding="utf-8")
        assert "Top 10 Riskiest Resources" in content

    def test_html_contains_permission_map(self, aws_report_files) -> None:
        html_path, _ = aws_report_files
        content = html_path.read_text(encoding="utf-8")
        assert "Permission Map" in content

    def test_html_contains_bar_chart(self, aws_report_files) -> None:
        html_path, _ = aws_report_files
        content = html_path.read_text(encoding="utf-8")
        assert "chart-bar" in content

    def test_html_contains_cli_snippets(self, aws_report_files) -> None:
        html_path, _ = aws_report_files
        content = html_path.read_text(encoding="utf-8")
        assert "<pre>" in content

    def test_html_no_external_dependencies(self, aws_report_files) -> None:
        """Report must be self-contained — no CDN links."""
        html_path, _ = aws_report_files
        content = html_path.read_text(encoding="utf-8")
        forbidden = ["cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "googleapis.com"]
        for cdn in forbidden:
            assert cdn not in content, f"External dependency found: {cdn}"

    def test_json_export_valid_structure(self, aws_report_files) -> None:
        _, json_path = aws_report_files
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert "risk_level" in data
        assert "top_risks" in data
        assert "remediation" in data
        assert "permission_map" in data

    def test_json_export_no_raw_html(self, aws_report_files) -> None:
        _, json_path = aws_report_files
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert "permission_map_json" not in data

    def test_azure_report_generated(self, tmp_path: Path) -> None:
        result, risk_report = _build_full_azure()
        planner = RemediationPlanner()
        plan = planner.plan(risk_report)
        gen = ExecutiveReportGenerator(output_dir=tmp_path)
        html_path, _ = gen.generate(result, risk_report, plan, base_name="azure_report")
        content = html_path.read_text(encoding="utf-8")
        assert "AZURE" in content
