from __future__ import annotations

from enum import Enum
from typing import Any

import structlog
from pydantic import BaseModel, Field

from analyzers.risk_scorer import RiskReport, RiskScore, RiskLevel

logger = structlog.get_logger(__name__)


class ActionType(str, Enum):
    ROTATE_KEYS = "ROTATE_KEYS"
    ENABLE_MFA = "ENABLE_MFA"
    REMOVE_POLICY = "REMOVE_POLICY"
    REPLACE_WILDCARD = "REPLACE_WILDCARD"
    RESTRICT_TRUST = "RESTRICT_TRUST"


class Priority(str, Enum):
    P1 = "P1"  # CRITICAL
    P2 = "P2"  # HIGH
    P3 = "P3"  # MEDIUM


class Effort(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RemediationAction(BaseModel):
    action_id: str
    resource_id: str
    resource_name: str
    resource_type: str
    provider: str
    action_type: ActionType
    priority: Priority
    effort: Effort
    description: str
    cli_snippet: str
    risk_score: int
    related_factors: list[str] = Field(default_factory=list)


class RemediationPlan(BaseModel):
    provider: str
    account_id: str | None = None
    total_actions: int = 0
    p1_count: int = 0
    p2_count: int = 0
    p3_count: int = 0
    actions: list[RemediationAction] = Field(default_factory=list)


def _priority_from_level(level: RiskLevel) -> Priority:
    if level == RiskLevel.CRITICAL:
        return Priority.P1
    if level == RiskLevel.HIGH:
        return Priority.P2
    return Priority.P3


def _aws_rotate_keys_snippet(resource_name: str, key_id: str = "<ACCESS_KEY_ID>") -> str:
    return (
        f"# Deactivate old key\n"
        f"aws iam update-access-key --user-name {resource_name} --access-key-id {key_id} --status Inactive\n"
        f"# Create new key\n"
        f"aws iam create-access-key --user-name {resource_name}"
    )


def _aws_enable_mfa_snippet(resource_name: str) -> str:
    return (
        f"# Create virtual MFA device\n"
        f"aws iam create-virtual-mfa-device --virtual-mfa-device-name {resource_name}-mfa \\\n"
        f"  --outfile /tmp/{resource_name}-mfa.png --bootstrap-method QRCodePNG\n"
        f"# Enable MFA for user (replace SERIAL_NUMBER and TOTP codes)\n"
        f"aws iam enable-mfa-device --user-name {resource_name} \\\n"
        f"  --serial-number <SERIAL_NUMBER> \\\n"
        f"  --authentication-code1 <CODE1> --authentication-code2 <CODE2>"
    )


def _aws_detach_policy_snippet(resource_name: str, policy_arn: str, resource_type: str) -> str:
    if resource_type == "user":
        return f"aws iam detach-user-policy --user-name {resource_name} --policy-arn {policy_arn}"
    return f"aws iam detach-role-policy --role-name {resource_name} --policy-arn {policy_arn}"


def _aws_restrict_trust_snippet(role_name: str) -> str:
    return (
        f"# Update trust policy to restrict to specific principals\n"
        f"aws iam update-assume-role-policy --role-name {role_name} \\\n"
        f"  --policy-document '{{\n"
        f'    "Version": "2012-10-17",\n'
        f'    "Statement": [{{\n'
        f'      "Effect": "Allow",\n'
        f'      "Principal": {{"AWS": "arn:aws:iam::<TRUSTED_ACCOUNT_ID>:root"}},\n'
        f'      "Action": "sts:AssumeRole",\n'
        f'      "Condition": {{"StringEquals": {{"sts:ExternalId": "<EXTERNAL_ID>"}}}}\n'
        f"    }}]\n"
        f"  }}'"
    )


def _azure_remove_assignment_snippet(assignment_id: str, scope: str) -> str:
    return (
        f"az role assignment delete \\\n"
        f"  --ids {assignment_id}"
    )


def _azure_enable_mfa_snippet(user_name: str) -> str:
    return (
        f"# Enforce MFA via Conditional Access Policy (Azure AD P1/P2 required)\n"
        f"az ad user update --id {user_name} --force-change-password-next-sign-in true\n"
        f"# Then configure Conditional Access Policy in Azure Portal:\n"
        f"# https://portal.azure.com/#blade/Microsoft_AAD_IAM/ConditionalAccessBlade/Policies"
    )


class RemediationPlanner:
    def plan(self, risk_report: RiskReport) -> RemediationPlan:
        actions: list[RemediationAction] = []
        action_counter = 0

        for score in risk_report.scores:
            if score.level == RiskLevel.LOW:
                continue  # Only plan for MEDIUM+

            priority = _priority_from_level(score.level)
            factor_names = [f.name for f in score.factors]

            if score.provider == "aws":
                new_actions = self._plan_aws(score, priority, factor_names, action_counter)
            else:
                new_actions = self._plan_azure(score, priority, factor_names, action_counter)

            action_counter += len(new_actions)
            actions.extend(new_actions)

        # Sort: P1 first, then P2, P3; within same priority by score desc
        priority_order = {Priority.P1: 0, Priority.P2: 1, Priority.P3: 2}
        actions.sort(key=lambda a: (priority_order[a.priority], -a.risk_score))

        plan = RemediationPlan(
            provider=risk_report.provider,
            account_id=risk_report.account_id,
            total_actions=len(actions),
            p1_count=sum(1 for a in actions if a.priority == Priority.P1),
            p2_count=sum(1 for a in actions if a.priority == Priority.P2),
            p3_count=sum(1 for a in actions if a.priority == Priority.P3),
            actions=actions,
        )
        logger.info(
            "remediation_planner.complete",
            total=plan.total_actions,
            p1=plan.p1_count,
            p2=plan.p2_count,
            p3=plan.p3_count,
        )
        return plan

    def _plan_aws(
        self,
        score: RiskScore,
        priority: Priority,
        factor_names: list[str],
        counter: int,
    ) -> list[RemediationAction]:
        actions: list[RemediationAction] = []

        if "stale_access_key" in factor_names:
            actions.append(RemediationAction(
                action_id=f"ACT-{counter + len(actions):04d}",
                resource_id=score.resource_id,
                resource_name=score.resource_name,
                resource_type=score.resource_type,
                provider=score.provider,
                action_type=ActionType.ROTATE_KEYS,
                priority=priority,
                effort=Effort.LOW,
                description=f"Rotate stale access key for user '{score.resource_name}'",
                cli_snippet=_aws_rotate_keys_snippet(score.resource_name),
                risk_score=score.score,
                related_factors=["stale_access_key"],
            ))

        if "no_mfa" in factor_names and score.resource_type == "user":
            actions.append(RemediationAction(
                action_id=f"ACT-{counter + len(actions):04d}",
                resource_id=score.resource_id,
                resource_name=score.resource_name,
                resource_type=score.resource_type,
                provider=score.provider,
                action_type=ActionType.ENABLE_MFA,
                priority=priority,
                effort=Effort.LOW,
                description=f"Enable MFA for user '{score.resource_name}'",
                cli_snippet=_aws_enable_mfa_snippet(score.resource_name),
                risk_score=score.score,
                related_factors=["no_mfa"],
            ))

        if "broad_policy" in factor_names:
            policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
            actions.append(RemediationAction(
                action_id=f"ACT-{counter + len(actions):04d}",
                resource_id=score.resource_id,
                resource_name=score.resource_name,
                resource_type=score.resource_type,
                provider=score.provider,
                action_type=ActionType.REMOVE_POLICY,
                priority=Priority.P1 if priority == Priority.P1 else Priority.P2,
                effort=Effort.MEDIUM,
                description=f"Remove overly broad policy from '{score.resource_name}'",
                cli_snippet=_aws_detach_policy_snippet(
                    score.resource_name, policy_arn, score.resource_type
                ),
                risk_score=score.score,
                related_factors=["broad_policy"],
            ))

        if "wildcard_action" in factor_names or "wildcard_resource" in factor_names:
            actions.append(RemediationAction(
                action_id=f"ACT-{counter + len(actions):04d}",
                resource_id=score.resource_id,
                resource_name=score.resource_name,
                resource_type=score.resource_type,
                provider=score.provider,
                action_type=ActionType.REPLACE_WILDCARD,
                priority=priority,
                effort=Effort.HIGH,
                description=(
                    f"Replace wildcard permissions for '{score.resource_name}' "
                    "with least-privilege policy"
                ),
                cli_snippet=(
                    f"# 1. Identify required permissions using IAM Access Analyzer\n"
                    f"aws accessanalyzer list-analyzed-resources --analyzer-arn <ANALYZER_ARN>\n"
                    f"# 2. Create least-privilege policy and attach it\n"
                    f"aws iam create-policy --policy-name {score.resource_name}-least-priv \\\n"
                    f"  --policy-document file://least_priv_policy.json\n"
                    f"aws iam attach-{'user' if score.resource_type == 'user' else 'role'}-policy \\\n"
                    f"  --{'user' if score.resource_type == 'user' else 'role'}-name {score.resource_name} \\\n"
                    f"  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/{score.resource_name}-least-priv"
                ),
                risk_score=score.score,
                related_factors=["wildcard_action", "wildcard_resource"],
            ))

        if "cross_account_trust" in factor_names:
            actions.append(RemediationAction(
                action_id=f"ACT-{counter + len(actions):04d}",
                resource_id=score.resource_id,
                resource_name=score.resource_name,
                resource_type=score.resource_type,
                provider=score.provider,
                action_type=ActionType.RESTRICT_TRUST,
                priority=Priority.P1,
                effort=Effort.MEDIUM,
                description=f"Restrict cross-account trust for role '{score.resource_name}'",
                cli_snippet=_aws_restrict_trust_snippet(score.resource_name),
                risk_score=score.score,
                related_factors=["cross_account_trust"],
            ))

        return actions

    def _plan_azure(
        self,
        score: RiskScore,
        priority: Priority,
        factor_names: list[str],
        counter: int,
    ) -> list[RemediationAction]:
        actions: list[RemediationAction] = []

        if "broad_policy" in factor_names or "wildcard_action" in factor_names:
            actions.append(RemediationAction(
                action_id=f"ACT-{counter + len(actions):04d}",
                resource_id=score.resource_id,
                resource_name=score.resource_name,
                resource_type=score.resource_type,
                provider=score.provider,
                action_type=ActionType.REMOVE_POLICY,
                priority=priority,
                effort=Effort.MEDIUM,
                description=f"Remove overly broad Azure role assignment for '{score.resource_name}'",
                cli_snippet=_azure_remove_assignment_snippet(score.resource_id, ""),
                risk_score=score.score,
                related_factors=factor_names,
            ))

        if "no_mfa" in factor_names and score.resource_type == "user":
            actions.append(RemediationAction(
                action_id=f"ACT-{counter + len(actions):04d}",
                resource_id=score.resource_id,
                resource_name=score.resource_name,
                resource_type=score.resource_type,
                provider=score.provider,
                action_type=ActionType.ENABLE_MFA,
                priority=priority,
                effort=Effort.LOW,
                description=f"Enforce MFA for Azure user '{score.resource_name}'",
                cli_snippet=_azure_enable_mfa_snippet(score.resource_name),
                risk_score=score.score,
                related_factors=["no_mfa"],
            ))

        if "wildcard_action" in factor_names and score.resource_type not in ("user",):
            actions.append(RemediationAction(
                action_id=f"ACT-{counter + len(actions):04d}",
                resource_id=score.resource_id,
                resource_name=score.resource_name,
                resource_type=score.resource_type,
                provider=score.provider,
                action_type=ActionType.REPLACE_WILDCARD,
                priority=priority,
                effort=Effort.HIGH,
                description=f"Replace wildcard Azure role definition for '{score.resource_name}'",
                cli_snippet=(
                    f"# Create a scoped custom role replacing the wildcard definition\n"
                    f"az role definition create --role-definition '{{\n"
                    f'  "Name": "{score.resource_name}-scoped",\n'
                    f'  "Actions": ["<specific/actions>"],\n'
                    f'  "AssignableScopes": ["/subscriptions/<SUB_ID>/resourceGroups/<RG_NAME>"]\n'
                    f"}}'"
                ),
                risk_score=score.score,
                related_factors=["wildcard_action"],
            ))

        return actions
