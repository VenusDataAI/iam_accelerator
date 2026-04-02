"""Tests for RiskScorer covering each risk factor."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from auditors.aws_auditor import AWSAuditor
from auditors.azure_auditor import AzureAuditor
from auditors.base_auditor import (
    AccessLevel,
    AuditPolicy,
    AuditResult,
    AuditRole,
    AuditServiceAccount,
    AuditUser,
    CloudProvider,
)
from analyzers.risk_scorer import RiskLevel, RiskScorer

SAMPLE_AWS = Path(__file__).parent.parent / "data" / "samples" / "aws_iam_sample.json"
SAMPLE_AZURE = Path(__file__).parent.parent / "data" / "samples" / "azure_rbac_sample.json"

now = datetime.now(tz=timezone.utc)


def _make_policy(
    name: str = "TestPolicy",
    wildcard_action: bool = False,
    wildcard_resource: bool = False,
    access_level: AccessLevel = AccessLevel.READ,
) -> AuditPolicy:
    return AuditPolicy(
        policy_id=name,
        policy_name=name,
        has_wildcard_action=wildcard_action,
        has_wildcard_resource=wildcard_resource,
        access_level=access_level,
        actions=["*"] if wildcard_action else ["s3:GetObject"],
        resources=["*"] if wildcard_resource else ["arn:aws:s3:::bucket/*"],
    )


def _make_user(
    name: str = "test-user",
    mfa: bool = True,
    last_activity_days_ago: int = 10,
    policies: list[AuditPolicy] | None = None,
    access_keys: list[dict] | None = None,
) -> AuditUser:
    return AuditUser(
        user_id=f"uid-{name}",
        user_name=name,
        mfa_enabled=mfa,
        last_activity=now - timedelta(days=last_activity_days_ago),
        attached_policies=policies or [],
        access_keys=access_keys or [],
        provider=CloudProvider.AWS,
    )


def _make_result(
    users: list[AuditUser] | None = None,
    roles: list[AuditRole] | None = None,
    service_accounts: list[AuditServiceAccount] | None = None,
) -> AuditResult:
    return AuditResult(
        provider=CloudProvider.AWS,
        users=users or [],
        roles=roles or [],
        service_accounts=service_accounts or [],
    )


@pytest.fixture
def scorer() -> RiskScorer:
    return RiskScorer()


# ---------------------------------------------------------------------------
# Individual risk factors
# ---------------------------------------------------------------------------

class TestWildcardActionFactor:
    def test_wildcard_action_increases_score(self, scorer: RiskScorer) -> None:
        policy = _make_policy(wildcard_action=True, wildcard_resource=True)
        user = _make_user(policies=[policy])
        result = _make_result(users=[user])
        report = scorer.score(result)
        score = report.scores[0]
        assert score.score >= 35
        factor_names = [f.name for f in score.factors]
        assert "wildcard_action" in factor_names

    def test_no_wildcard_no_factor(self, scorer: RiskScorer) -> None:
        policy = _make_policy(wildcard_action=False)
        user = _make_user(policies=[policy])
        result = _make_result(users=[user])
        report = scorer.score(result)
        factor_names = [f.name for f in report.scores[0].factors]
        assert "wildcard_action" not in factor_names


class TestStaleCredentialFactor:
    def test_stale_credential_detected(self, scorer: RiskScorer) -> None:
        policy = _make_policy()
        user = _make_user(policies=[policy], last_activity_days_ago=100)
        result = _make_result(users=[user])
        report = scorer.score(result)
        factor_names = [f.name for f in report.scores[0].factors]
        assert "stale_credential" in factor_names

    def test_fresh_credential_not_flagged(self, scorer: RiskScorer) -> None:
        policy = _make_policy()
        user = _make_user(policies=[policy], last_activity_days_ago=5)
        result = _make_result(users=[user])
        report = scorer.score(result)
        factor_names = [f.name for f in report.scores[0].factors]
        assert "stale_credential" not in factor_names


class TestMFAFactor:
    def test_missing_mfa_flagged(self, scorer: RiskScorer) -> None:
        policy = _make_policy()
        user = _make_user(mfa=False, policies=[policy])
        result = _make_result(users=[user])
        report = scorer.score(result)
        factor_names = [f.name for f in report.scores[0].factors]
        assert "no_mfa" in factor_names

    def test_mfa_enabled_not_flagged(self, scorer: RiskScorer) -> None:
        policy = _make_policy()
        user = _make_user(mfa=True, policies=[policy])
        result = _make_result(users=[user])
        report = scorer.score(result)
        factor_names = [f.name for f in report.scores[0].factors]
        assert "no_mfa" not in factor_names


class TestStaleKeyFactor:
    def test_stale_active_key_flagged(self, scorer: RiskScorer) -> None:
        stale_date = (now - timedelta(days=120)).isoformat()
        key = {"AccessKeyId": "AKIAOLD", "Status": "Active", "LastUsedDate": stale_date}
        user = _make_user(mfa=True, access_keys=[key])
        result = _make_result(users=[user])
        report = scorer.score(result)
        factor_names = [f.name for f in report.scores[0].factors]
        assert "stale_access_key" in factor_names

    def test_inactive_key_not_flagged(self, scorer: RiskScorer) -> None:
        stale_date = (now - timedelta(days=120)).isoformat()
        key = {"AccessKeyId": "AKIAOLD", "Status": "Inactive", "LastUsedDate": stale_date}
        user = _make_user(mfa=True, access_keys=[key])
        result = _make_result(users=[user])
        report = scorer.score(result)
        factor_names = [f.name for f in report.scores[0].factors]
        assert "stale_access_key" not in factor_names


class TestCrossAccountFactor:
    def test_cross_account_role_flagged(self, scorer: RiskScorer) -> None:
        role = AuditRole(
            role_id="r1",
            role_name="cross-role",
            is_cross_account=True,
            trust_principals=["arn:aws:iam::999999:root"],
            provider=CloudProvider.AWS,
        )
        result = _make_result(roles=[role])
        report = scorer.score(result)
        factor_names = [f.name for f in report.scores[0].factors]
        assert "cross_account_trust" in factor_names

    def test_internal_role_not_flagged(self, scorer: RiskScorer) -> None:
        role = AuditRole(
            role_id="r2",
            role_name="service-role",
            is_service_role=True,
            is_cross_account=False,
            provider=CloudProvider.AWS,
        )
        result = _make_result(roles=[role])
        report = scorer.score(result)
        factor_names = [f.name for f in report.scores[0].factors]
        assert "cross_account_trust" not in factor_names


class TestBroadPolicyFactor:
    def test_administrator_access_flagged(self, scorer: RiskScorer) -> None:
        policy = _make_policy(name="AdministratorAccess", wildcard_action=True)
        user = _make_user(mfa=True, policies=[policy])
        result = _make_result(users=[user])
        report = scorer.score(result)
        factor_names = [f.name for f in report.scores[0].factors]
        assert "broad_policy" in factor_names


# ---------------------------------------------------------------------------
# Overall risk level
# ---------------------------------------------------------------------------

class TestOverallRiskLevel:
    def test_critical_level_when_high_score(self, scorer: RiskScorer) -> None:
        policy = _make_policy(wildcard_action=True, wildcard_resource=True,
                              name="AdministratorAccess")
        stale_date = (now - timedelta(days=200)).isoformat()
        key = {"AccessKeyId": "K1", "Status": "Active", "LastUsedDate": stale_date}
        user = _make_user(mfa=False, policies=[policy],
                          last_activity_days_ago=200, access_keys=[key])
        result = _make_result(users=[user])
        report = scorer.score(result)
        assert report.risk_level == RiskLevel.CRITICAL

    def test_low_level_clean_user(self, scorer: RiskScorer) -> None:
        policy = _make_policy()
        user = _make_user(mfa=True, policies=[policy], last_activity_days_ago=5)
        result = _make_result(users=[user])
        report = scorer.score(result)
        assert report.risk_level == RiskLevel.LOW

    def test_empty_result_is_low(self, scorer: RiskScorer) -> None:
        result = _make_result()
        report = scorer.score(result)
        assert report.risk_level == RiskLevel.LOW
        assert report.total_resources == 0


# ---------------------------------------------------------------------------
# Top 10 ranking
# ---------------------------------------------------------------------------

class TestTopRisks:
    def test_top_risks_max_10(self, scorer: RiskScorer) -> None:
        users = [
            _make_user(
                name=f"u{i}",
                mfa=False,
                policies=[_make_policy(wildcard_action=True, wildcard_resource=True,
                                       name="AdministratorAccess")],
            )
            for i in range(15)
        ]
        result = _make_result(users=users)
        report = scorer.score(result)
        assert len(report.top_risks) == 10

    def test_top_risks_sorted_descending(self, scorer: RiskScorer) -> None:
        risky = _make_user(
            name="risky",
            mfa=False,
            policies=[_make_policy(wildcard_action=True, wildcard_resource=True)],
        )
        safe = _make_user(name="safe", mfa=True, policies=[_make_policy()])
        result = _make_result(users=[safe, risky])
        report = scorer.score(result)
        scores = [s.score for s in report.top_risks]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# Integration: sample data
# ---------------------------------------------------------------------------

class TestSampleDataScoring:
    def test_aws_sample_has_critical_findings(self, scorer: RiskScorer) -> None:
        auditor = AWSAuditor(sample_data_path=SAMPLE_AWS)
        result = auditor.run()
        report = scorer.score(result)
        assert report.critical_count > 0

    def test_azure_sample_scores(self, scorer: RiskScorer) -> None:
        auditor = AzureAuditor(
            subscription_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            sample_data_path=SAMPLE_AZURE,
        )
        result = auditor.run()
        report = scorer.score(result)
        assert report.total_resources > 0
