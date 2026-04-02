from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

import structlog
from pydantic import BaseModel, Field

from auditors.base_auditor import AuditResult, AuditRole, AuditUser, AuditServiceAccount

logger = structlog.get_logger(__name__)

# Stale threshold in days
STALE_DAYS = 90
STALE_KEY_DAYS = 90

# Risk weights (sum to 100 max per factor)
WEIGHT_WILDCARD_ACTION = 35
WEIGHT_WILDCARD_RESOURCE = 15
WEIGHT_BROAD_POLICY = 20
WEIGHT_STALE_CREDENTIAL = 15
WEIGHT_NO_MFA = 10
WEIGHT_CROSS_ACCOUNT = 20
WEIGHT_PUBLIC_ROLE = 30
WEIGHT_STALE_KEY = 15

BROAD_POLICY_NAMES = {
    "AdministratorAccess",
    "PowerUserAccess",
    "Owner",
    "Contributor",
    "AmazonS3FullAccess",
    "FullAccess",
}


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskFactor(BaseModel):
    name: str
    score_contribution: int
    description: str


class RiskScore(BaseModel):
    resource_id: str
    resource_name: str
    resource_type: str
    provider: str
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    factors: list[RiskFactor] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class RiskReport(BaseModel):
    audited_at: datetime = Field(default_factory=datetime.utcnow)
    provider: str
    account_id: str | None = None
    scores: list[RiskScore] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    top_risks: list[RiskScore] = Field(default_factory=list)
    total_resources: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


def _level_from_score(score: int) -> RiskLevel:
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _days_since(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(tz=timezone.utc)
    return (now - dt).days


class RiskScorer:
    def score(self, audit_result: AuditResult) -> RiskReport:
        scores: list[RiskScore] = []

        for user in audit_result.users:
            scores.append(self._score_user(user))

        for role in audit_result.roles:
            scores.append(self._score_role(role))

        for sa in audit_result.service_accounts:
            scores.append(self._score_service_account(sa))

        top_10 = sorted(scores, key=lambda s: s.score, reverse=True)[:10]
        overall = self._overall_level(scores)

        report = RiskReport(
            provider=audit_result.provider.value,
            account_id=audit_result.account_id,
            scores=scores,
            risk_level=overall,
            top_risks=top_10,
            total_resources=len(scores),
            critical_count=sum(1 for s in scores if s.level == RiskLevel.CRITICAL),
            high_count=sum(1 for s in scores if s.level == RiskLevel.HIGH),
            medium_count=sum(1 for s in scores if s.level == RiskLevel.MEDIUM),
            low_count=sum(1 for s in scores if s.level == RiskLevel.LOW),
        )
        logger.info(
            "risk_scorer.complete",
            total=report.total_resources,
            risk_level=report.risk_level,
            critical=report.critical_count,
        )
        return report

    # ------------------------------------------------------------------
    # Per-resource scorers
    # ------------------------------------------------------------------

    def _score_user(self, user: AuditUser) -> RiskScore:
        raw_score = 0
        factors: list[RiskFactor] = []

        all_policies = user.attached_policies + user.inline_policies

        # Wildcard action
        if any(p.has_wildcard_action for p in all_policies):
            raw_score += WEIGHT_WILDCARD_ACTION
            factors.append(RiskFactor(
                name="wildcard_action",
                score_contribution=WEIGHT_WILDCARD_ACTION,
                description="One or more policies allow wildcard (*) actions",
            ))

        # Wildcard resource
        if any(p.has_wildcard_resource for p in all_policies):
            raw_score += WEIGHT_WILDCARD_RESOURCE
            factors.append(RiskFactor(
                name="wildcard_resource",
                score_contribution=WEIGHT_WILDCARD_RESOURCE,
                description="One or more policies apply to all resources (*)",
            ))

        # Broad policy attached
        broad = [p.policy_name for p in all_policies if p.policy_name in BROAD_POLICY_NAMES]
        if broad:
            raw_score += WEIGHT_BROAD_POLICY
            factors.append(RiskFactor(
                name="broad_policy",
                score_contribution=WEIGHT_BROAD_POLICY,
                description=f"Overly broad policies attached: {', '.join(broad)}",
            ))

        # Stale credential
        days = _days_since(user.last_activity)
        if days is not None and days > STALE_DAYS:
            raw_score += WEIGHT_STALE_CREDENTIAL
            factors.append(RiskFactor(
                name="stale_credential",
                score_contribution=WEIGHT_STALE_CREDENTIAL,
                description=f"Last activity {days} days ago (threshold: {STALE_DAYS})",
            ))

        # Missing MFA
        if not user.mfa_enabled and all_policies:
            raw_score += WEIGHT_NO_MFA
            factors.append(RiskFactor(
                name="no_mfa",
                score_contribution=WEIGHT_NO_MFA,
                description="MFA is not enabled for this user",
            ))

        # Stale access keys
        for key in user.access_keys:
            last_used = key.get("LastUsedDate") or key.get("CreateDate")
            if last_used:
                if isinstance(last_used, str):
                    last_used = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                key_days = _days_since(last_used)
                if key_days is not None and key_days > STALE_KEY_DAYS and key.get("Status") == "Active":
                    raw_score += WEIGHT_STALE_KEY
                    factors.append(RiskFactor(
                        name="stale_access_key",
                        score_contribution=WEIGHT_STALE_KEY,
                        description=f"Access key {key.get('AccessKeyId', 'unknown')} unused for {key_days} days",
                    ))
                    break  # count once

        score = min(raw_score, 100)
        return RiskScore(
            resource_id=user.user_id,
            resource_name=user.user_name,
            resource_type="user",
            provider=user.provider.value,
            score=score,
            level=_level_from_score(score),
            factors=factors,
        )

    def _score_role(self, role: AuditRole) -> RiskScore:
        raw_score = 0
        factors: list[RiskFactor] = []

        all_policies = role.attached_policies + role.inline_policies

        if any(p.has_wildcard_action for p in all_policies):
            raw_score += WEIGHT_WILDCARD_ACTION
            factors.append(RiskFactor(
                name="wildcard_action",
                score_contribution=WEIGHT_WILDCARD_ACTION,
                description="Role allows wildcard (*) actions",
            ))

        if any(p.has_wildcard_resource for p in all_policies):
            raw_score += WEIGHT_WILDCARD_RESOURCE
            factors.append(RiskFactor(
                name="wildcard_resource",
                score_contribution=WEIGHT_WILDCARD_RESOURCE,
                description="Role applies to all resources (*)",
            ))

        broad = [p.policy_name for p in all_policies if p.policy_name in BROAD_POLICY_NAMES]
        if broad:
            raw_score += WEIGHT_BROAD_POLICY
            factors.append(RiskFactor(
                name="broad_policy",
                score_contribution=WEIGHT_BROAD_POLICY,
                description=f"Overly broad policies: {', '.join(broad)}",
            ))

        if role.is_cross_account:
            raw_score += WEIGHT_CROSS_ACCOUNT
            factors.append(RiskFactor(
                name="cross_account_trust",
                score_contribution=WEIGHT_CROSS_ACCOUNT,
                description=f"Role trusts external account(s): {', '.join(role.trust_principals)}",
            ))

        if role.is_public:
            raw_score += WEIGHT_PUBLIC_ROLE
            factors.append(RiskFactor(
                name="public_role",
                score_contribution=WEIGHT_PUBLIC_ROLE,
                description="Role trust policy allows any principal (*)",
            ))

        score = min(raw_score, 100)
        return RiskScore(
            resource_id=role.role_id,
            resource_name=role.role_name,
            resource_type="role",
            provider=role.provider.value,
            score=score,
            level=_level_from_score(score),
            factors=factors,
        )

    def _score_service_account(self, sa: AuditServiceAccount) -> RiskScore:
        raw_score = 0
        factors: list[RiskFactor] = []

        for p in sa.attached_policies:
            if p.has_wildcard_action:
                raw_score += WEIGHT_WILDCARD_ACTION
                factors.append(RiskFactor(
                    name="wildcard_action",
                    score_contribution=WEIGHT_WILDCARD_ACTION,
                    description="Service account has wildcard action permissions",
                ))
                break

        broad = [p.policy_name for p in sa.attached_policies if p.policy_name in BROAD_POLICY_NAMES]
        if broad:
            raw_score += WEIGHT_BROAD_POLICY
            factors.append(RiskFactor(
                name="broad_policy",
                score_contribution=WEIGHT_BROAD_POLICY,
                description=f"Broad policies: {', '.join(broad)}",
            ))

        score = min(raw_score, 100)
        return RiskScore(
            resource_id=sa.account_id,
            resource_name=sa.account_name,
            resource_type="service_account",
            provider=sa.provider.value,
            score=score,
            level=_level_from_score(score),
            factors=factors,
        )

    @staticmethod
    def _overall_level(scores: list[RiskScore]) -> RiskLevel:
        if not scores:
            return RiskLevel.LOW
        if any(s.level == RiskLevel.CRITICAL for s in scores):
            return RiskLevel.CRITICAL
        if any(s.level == RiskLevel.HIGH for s in scores):
            return RiskLevel.HIGH
        if any(s.level == RiskLevel.MEDIUM for s in scores):
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
