"""Tests for AWSAuditor using the bundled sample JSON."""
from __future__ import annotations

from pathlib import Path

import pytest

from auditors.aws_auditor import AWSAuditor
from auditors.base_auditor import AccessLevel, CloudProvider

SAMPLE_PATH = Path(__file__).parent.parent / "data" / "samples" / "aws_iam_sample.json"


@pytest.fixture
def auditor() -> AWSAuditor:
    return AWSAuditor(
        account_id="123456789012",
        account_name="test-account",
        sample_data_path=SAMPLE_PATH,
    )


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class TestAWSAuditUsers:
    def test_user_count(self, auditor: AWSAuditor) -> None:
        users = auditor.audit_users()
        assert len(users) == 5

    def test_user_provider(self, auditor: AWSAuditor) -> None:
        users = auditor.audit_users()
        assert all(u.provider == CloudProvider.AWS for u in users)

    def test_admin_user_no_mfa(self, auditor: AWSAuditor) -> None:
        users = {u.user_name: u for u in auditor.audit_users()}
        assert not users["admin-user"].mfa_enabled

    def test_developer_has_mfa(self, auditor: AWSAuditor) -> None:
        users = {u.user_name: u for u in auditor.audit_users()}
        assert users["developer-alice"].mfa_enabled

    def test_admin_has_administrator_access(self, auditor: AWSAuditor) -> None:
        users = {u.user_name: u for u in auditor.audit_users()}
        policy_names = [p.policy_name for p in users["admin-user"].attached_policies]
        assert "AdministratorAccess" in policy_names

    def test_ops_user_has_inline_policy(self, auditor: AWSAuditor) -> None:
        users = {u.user_name: u for u in auditor.audit_users()}
        assert len(users["ops-bob"].inline_policies) == 1
        inline = users["ops-bob"].inline_policies[0]
        assert inline.has_wildcard_action
        assert inline.has_wildcard_resource

    def test_user_access_keys_parsed(self, auditor: AWSAuditor) -> None:
        users = {u.user_name: u for u in auditor.audit_users()}
        assert len(users["admin-user"].access_keys) == 1
        assert users["readonly-charlie"].access_keys == []

    def test_last_activity_parsed(self, auditor: AWSAuditor) -> None:
        users = {u.user_name: u for u in auditor.audit_users()}
        assert users["developer-alice"].last_activity is not None

    def test_created_at_parsed(self, auditor: AWSAuditor) -> None:
        users = {u.user_name: u for u in auditor.audit_users()}
        assert users["admin-user"].created_at is not None


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

class TestAWSAuditRoles:
    def test_role_count(self, auditor: AWSAuditor) -> None:
        roles = auditor.audit_roles()
        assert len(roles) == 3

    def test_lambda_role_is_service_role(self, auditor: AWSAuditor) -> None:
        roles = {r.role_name: r for r in auditor.audit_roles()}
        assert roles["lambda-execution-role"].is_service_role
        assert not roles["lambda-execution-role"].is_cross_account

    def test_cross_account_role_detected(self, auditor: AWSAuditor) -> None:
        roles = {r.role_name: r for r in auditor.audit_roles()}
        assert roles["cross-account-admin-role"].is_cross_account

    def test_cross_account_role_has_admin_policy(self, auditor: AWSAuditor) -> None:
        roles = {r.role_name: r for r in auditor.audit_roles()}
        role = roles["cross-account-admin-role"]
        policy_names = [p.policy_name for p in role.attached_policies]
        assert "AdministratorAccess" in policy_names

    def test_ec2_role_inline_wildcard(self, auditor: AWSAuditor) -> None:
        roles = {r.role_name: r for r in auditor.audit_roles()}
        role = roles["ec2-instance-profile-role"]
        assert any(p.has_wildcard_action for p in role.inline_policies)

    def test_role_provider(self, auditor: AWSAuditor) -> None:
        roles = auditor.audit_roles()
        assert all(r.provider == CloudProvider.AWS for r in roles)


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

class TestAWSAuditPolicies:
    def test_policy_count(self, auditor: AWSAuditor) -> None:
        policies = auditor.audit_policies()
        assert len(policies) == 2

    def test_wildcard_policy_detected(self, auditor: AWSAuditor) -> None:
        policies = {p.policy_name: p for p in auditor.audit_policies()}
        assert policies["CustomWildcardPolicy"].has_wildcard_action
        assert policies["CustomWildcardPolicy"].has_wildcard_resource

    def test_least_priv_policy_not_wildcard(self, auditor: AWSAuditor) -> None:
        policies = {p.policy_name: p for p in auditor.audit_policies()}
        lp = policies["LeastPrivilegePolicy"]
        assert not lp.has_wildcard_action
        assert not lp.has_wildcard_resource
        assert lp.access_level == AccessLevel.READ


# ---------------------------------------------------------------------------
# Service accounts
# ---------------------------------------------------------------------------

class TestAWSServiceAccounts:
    def test_service_accounts_empty(self, auditor: AWSAuditor) -> None:
        assert auditor.audit_service_accounts() == []


# ---------------------------------------------------------------------------
# Full run
# ---------------------------------------------------------------------------

class TestAWSFullRun:
    def test_run_returns_audit_result(self, auditor: AWSAuditor) -> None:
        result = auditor.run()
        assert result.provider == CloudProvider.AWS
        assert result.total_resources > 0
        assert result.account_id == "123456789012"

    def test_run_with_boto3_mock(self, mocker) -> None:
        """Ensure the auditor uses the boto3 client when no sample data is provided."""
        mock_client = mocker.MagicMock()
        mock_client.get_account_authorization_details.return_value = {
            "UserDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
        }
        aud = AWSAuditor(account_id="111", boto3_client=mock_client)
        result = aud.run()
        assert result.total_resources == 0
        assert mock_client.get_account_authorization_details.call_count >= 1
