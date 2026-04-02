from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from auditors.base_auditor import (
    AccessLevel,
    AuditPolicy,
    AuditResult,
    AuditRole,
    AuditServiceAccount,
    AuditUser,
    BaseAuditor,
    CloudProvider,
)

logger = structlog.get_logger(__name__)

BROAD_POLICIES = {
    "AdministratorAccess",
    "PowerUserAccess",
    "AmazonS3FullAccess",
}


def _classify_access(actions: list[str]) -> AccessLevel:
    if not actions:
        return AccessLevel.UNKNOWN
    for action in actions:
        if action in ("*", "AdministratorAccess"):
            return AccessLevel.ADMIN
        if action.endswith(":*") or action.endswith("FullAccess"):
            return AccessLevel.ADMIN
        if ":Write" in action or ":Put" in action or ":Create" in action or ":Delete" in action:
            return AccessLevel.WRITE
    return AccessLevel.READ


def _parse_policy_document(doc: dict[str, Any]) -> tuple[list[str], list[str], bool, bool]:
    actions: list[str] = []
    resources: list[str] = []
    has_wildcard_action = False
    has_wildcard_resource = False

    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        raw_actions = stmt.get("Action", [])
        raw_resources = stmt.get("Resource", [])
        if isinstance(raw_actions, str):
            raw_actions = [raw_actions]
        if isinstance(raw_resources, str):
            raw_resources = [raw_resources]
        actions.extend(raw_actions)
        resources.extend(raw_resources)
        if "*" in raw_actions or any(a.endswith(":*") for a in raw_actions):
            has_wildcard_action = True
        if "*" in raw_resources:
            has_wildcard_resource = True

    return actions, resources, has_wildcard_action, has_wildcard_resource


class AWSAuditor(BaseAuditor):
    """
    Audits AWS IAM using boto3.

    When ``sample_data_path`` is provided the auditor reads from the local JSON
    file instead of calling real AWS APIs – useful for offline testing and demos.
    """

    def __init__(
        self,
        account_id: str | None = None,
        account_name: str | None = None,
        boto3_client: Any | None = None,
        sample_data_path: str | Path | None = None,
    ) -> None:
        super().__init__(account_id=account_id, account_name=account_name)
        self._client = boto3_client
        self._sample_data: dict[str, Any] | None = None

        if sample_data_path:
            path = Path(sample_data_path)
            with path.open() as fh:
                self._sample_data = json.load(fh)
            logger.info("aws_auditor.sample_mode", path=str(path))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_authorization_details(self) -> dict[str, Any]:
        if self._sample_data is not None:
            return self._sample_data
        if self._client is None:
            raise RuntimeError("No boto3 client and no sample data provided.")
        return self._client.get_account_authorization_details(
            Filter=["User", "Role", "LocalManagedPolicy", "AWSManagedPolicy"]
        )

    def _build_policy(
        self,
        policy_name: str,
        policy_arn: str | None,
        doc: dict[str, Any],
        is_managed: bool = True,
        is_inline: bool = False,
    ) -> AuditPolicy:
        actions, resources, wildcard_action, wildcard_resource = _parse_policy_document(doc)
        return AuditPolicy(
            policy_id=policy_arn or policy_name,
            policy_name=policy_name,
            policy_arn=policy_arn,
            is_managed=is_managed,
            is_inline=is_inline,
            actions=actions,
            resources=resources,
            has_wildcard_action=wildcard_action,
            has_wildcard_resource=wildcard_resource,
            access_level=_classify_access(actions),
            raw=doc,
        )

    # ------------------------------------------------------------------
    # BaseAuditor implementation
    # ------------------------------------------------------------------

    def audit_users(self) -> list[AuditUser]:
        details = self._get_authorization_details()
        users: list[AuditUser] = []

        for raw_user in details.get("UserDetailList", []):
            attached: list[AuditPolicy] = []
            for p in raw_user.get("AttachedManagedPolicies", []):
                attached.append(
                    AuditPolicy(
                        policy_id=p["PolicyArn"],
                        policy_name=p["PolicyName"],
                        policy_arn=p["PolicyArn"],
                        is_managed=True,
                        has_wildcard_action=p["PolicyName"] in BROAD_POLICIES,
                        access_level=(
                            AccessLevel.ADMIN if p["PolicyName"] in BROAD_POLICIES else AccessLevel.UNKNOWN
                        ),
                        raw=p,
                    )
                )

            inline: list[AuditPolicy] = []
            for ip in raw_user.get("UserPolicyList", []):
                doc = ip.get("PolicyDocument", {})
                inline.append(
                    self._build_policy(
                        policy_name=ip["PolicyName"],
                        policy_arn=None,
                        doc=doc,
                        is_managed=False,
                        is_inline=True,
                    )
                )

            last_activity: datetime | None = None
            raw_last_used = raw_user.get("PasswordLastUsed")
            if raw_last_used:
                if isinstance(raw_last_used, datetime):
                    last_activity = raw_last_used
                else:
                    last_activity = datetime.fromisoformat(raw_last_used.replace("Z", "+00:00"))

            created_at: datetime | None = None
            raw_create = raw_user.get("CreateDate")
            if raw_create:
                if isinstance(raw_create, datetime):
                    created_at = raw_create
                else:
                    created_at = datetime.fromisoformat(raw_create.replace("Z", "+00:00"))

            mfa_enabled = bool(raw_user.get("MFADevices"))

            users.append(
                AuditUser(
                    user_id=raw_user["UserId"],
                    user_name=raw_user["UserName"],
                    arn=raw_user.get("Arn"),
                    created_at=created_at,
                    last_activity=last_activity,
                    mfa_enabled=mfa_enabled,
                    attached_policies=attached,
                    inline_policies=inline,
                    access_keys=raw_user.get("AccessKeys", []),
                    provider=CloudProvider.AWS,
                    raw=raw_user,
                )
            )

        logger.info("aws_auditor.users_collected", count=len(users))
        return users

    def audit_roles(self) -> list[AuditRole]:
        details = self._get_authorization_details()
        roles: list[AuditRole] = []

        for raw_role in details.get("RoleDetailList", []):
            attached: list[AuditPolicy] = []
            for p in raw_role.get("AttachedManagedPolicies", []):
                attached.append(
                    AuditPolicy(
                        policy_id=p["PolicyArn"],
                        policy_name=p["PolicyName"],
                        policy_arn=p["PolicyArn"],
                        is_managed=True,
                        has_wildcard_action=p["PolicyName"] in BROAD_POLICIES or p["PolicyName"] == "AdministratorAccess",
                        access_level=(
                            AccessLevel.ADMIN
                            if p["PolicyName"] in {"AdministratorAccess", "PowerUserAccess"}
                            else AccessLevel.UNKNOWN
                        ),
                        raw=p,
                    )
                )

            inline: list[AuditPolicy] = []
            for ip in raw_role.get("RolePolicyList", []):
                doc = ip.get("PolicyDocument", {})
                inline.append(
                    self._build_policy(
                        policy_name=ip["PolicyName"],
                        policy_arn=None,
                        doc=doc,
                        is_managed=False,
                        is_inline=True,
                    )
                )

            trust_doc = raw_role.get("AssumeRolePolicyDocument", {})
            trust_principals: list[str] = []
            is_cross_account = False
            is_public = False
            is_service_role = False

            account_id = self.account_id or ""

            for stmt in trust_doc.get("Statement", []):
                principal = stmt.get("Principal", {})
                if principal == "*":
                    is_public = True
                    trust_principals.append("*")
                    continue
                if isinstance(principal, dict):
                    for key, val in principal.items():
                        vals = [val] if isinstance(val, str) else val
                        for v in vals:
                            trust_principals.append(v)
                            if key == "Service":
                                is_service_role = True
                            elif key == "AWS" and account_id and account_id not in v:
                                is_cross_account = True
                            elif key == "AWS" and not account_id and "root" in v:
                                is_cross_account = True

            created_at: datetime | None = None
            raw_create = raw_role.get("CreateDate")
            if raw_create:
                if isinstance(raw_create, datetime):
                    created_at = raw_create
                else:
                    created_at = datetime.fromisoformat(raw_create.replace("Z", "+00:00"))

            roles.append(
                AuditRole(
                    role_id=raw_role["RoleId"],
                    role_name=raw_role["RoleName"],
                    arn=raw_role.get("Arn"),
                    created_at=created_at,
                    attached_policies=attached,
                    inline_policies=inline,
                    trust_principals=trust_principals,
                    is_cross_account=is_cross_account,
                    is_public=is_public,
                    is_service_role=is_service_role,
                    provider=CloudProvider.AWS,
                    raw=raw_role,
                )
            )

        logger.info("aws_auditor.roles_collected", count=len(roles))
        return roles

    def audit_policies(self) -> list[AuditPolicy]:
        details = self._get_authorization_details()
        policies: list[AuditPolicy] = []

        for raw_policy in details.get("Policies", []):
            default_version = raw_policy.get("DefaultVersionId", "v1")
            doc: dict[str, Any] = {}
            for ver in raw_policy.get("PolicyVersionList", []):
                if ver.get("VersionId") == default_version or ver.get("IsDefaultVersion"):
                    doc = ver.get("Document", {})
                    break

            policies.append(
                self._build_policy(
                    policy_name=raw_policy["PolicyName"],
                    policy_arn=raw_policy.get("Arn"),
                    doc=doc,
                    is_managed=True,
                    is_inline=False,
                )
            )

        logger.info("aws_auditor.policies_collected", count=len(policies))
        return policies

    def audit_service_accounts(self) -> list[AuditServiceAccount]:
        # AWS does not have a separate service account concept distinct from roles;
        # service roles are captured in audit_roles(). Return empty list.
        return []

    def _provider(self) -> CloudProvider:
        return CloudProvider.AWS
