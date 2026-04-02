from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape

from analyzers.permission_mapper import PermissionMapper
from analyzers.remediation_planner import RemediationPlan
from analyzers.risk_scorer import RiskReport, RiskScore
from auditors.base_auditor import AuditResult

logger = structlog.get_logger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"


class ExecutiveReportGenerator:
    def __init__(self, output_dir: str | Path = ".") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    def generate(
        self,
        audit_result: AuditResult,
        risk_report: RiskReport,
        remediation_plan: RemediationPlan,
        base_name: str = "iam_report",
    ) -> tuple[Path, Path]:
        """
        Generate HTML + JSON reports.

        Returns (html_path, json_path).
        """
        mapper = PermissionMapper()
        permission_graph = mapper.build(audit_result)

        context = self._build_context(risk_report, remediation_plan, permission_graph)

        html_path = self._render_html(context, base_name)
        json_path = self._render_json(context, base_name)

        logger.info(
            "executive_report.generated",
            html=str(html_path),
            json=str(json_path),
        )
        return html_path, json_path

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_context(
        self,
        risk_report: RiskReport,
        remediation_plan: RemediationPlan,
        permission_graph: dict[str, Any],
    ) -> dict[str, Any]:
        top_risks = [self._score_to_dict(s) for s in risk_report.top_risks]
        all_scores = [self._score_to_dict(s) for s in risk_report.scores]

        remediation_dict = {
            "total_actions": remediation_plan.total_actions,
            "p1_count": remediation_plan.p1_count,
            "p2_count": remediation_plan.p2_count,
            "p3_count": remediation_plan.p3_count,
            "actions": [a.model_dump() for a in remediation_plan.actions],
        }

        return {
            "provider": risk_report.provider,
            "account_id": risk_report.account_id,
            "audited_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "risk_level": risk_report.risk_level.value,
            "total_resources": risk_report.total_resources,
            "critical_count": risk_report.critical_count,
            "high_count": risk_report.high_count,
            "medium_count": risk_report.medium_count,
            "low_count": risk_report.low_count,
            "top_risks": top_risks,
            "all_scores": all_scores,
            "remediation": remediation_dict,
            "permission_map": permission_graph,
            "permission_map_json": json.dumps(permission_graph, default=str),
        }

    def _score_to_dict(self, score: RiskScore) -> dict[str, Any]:
        return {
            "resource_id": score.resource_id,
            "resource_name": score.resource_name,
            "resource_type": score.resource_type,
            "provider": score.provider,
            "score": score.score,
            "level": score.level.value,
            "factors": [f.model_dump() for f in score.factors],
        }

    def _render_html(self, context: dict[str, Any], base_name: str) -> Path:
        template = self._env.get_template("report_template.html")
        html_content = template.render(**context)
        path = self.output_dir / f"{base_name}.html"
        path.write_text(html_content, encoding="utf-8")
        logger.info("executive_report.html_written", path=str(path))
        return path

    def _render_json(self, context: dict[str, Any], base_name: str) -> Path:
        # Remove raw HTML string from JSON export; keep structured data
        export = {k: v for k, v in context.items() if k != "permission_map_json"}
        path = self.output_dir / f"{base_name}.json"
        path.write_text(json.dumps(export, indent=2, default=str), encoding="utf-8")
        logger.info("executive_report.json_written", path=str(path))
        return path
