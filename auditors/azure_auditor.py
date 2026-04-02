from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from auditors.base_auditor import (
    AccessLevel,
    AuditPolicy,
    AuditRole,
    AuditServiceAccount,
    AuditUser,
    BaseAuditor,
    CloudProvider,
)

logger = structlog.get_logger(__name__)

SUBSCRIPTION_SCOPE_PREFIX = "/subscriptions/"
OWNER_ROLE = "Owner"
CONTRIBUTOR_ROLE = "Contributor"


def _classify_azure_access(actions: list[str]) -> AccessLevel:
    if not actions:
        return AccessLevel.UNKNOWN
    for action in actions:
        if action == "*":
            return AccessLevel.ADMIN
        if action.endswith("/*"):
            return AccessLevel.ADMIN
    for action in actions:
        if "/write" in action.lower() or "/delete" in action.lower():
            return AccessLevel.WRITE
    return AccessLevel.READ


class AzureAuditor(BaseAuditor):
    """
    Audits Azure RBAC using azure-mgmt-authorization.

    When ``sample_data_path`` is provided the auditor reads from the local JSON
    file instead of calling real Azure APIs.
    """

    def __init__(
        self,
        subscription_id: str | None = None,
        account_name: str | None = None,
        auth_client: Any | None = None,
        sample_data_path: str | Path | None = None,
    ) -> None:
        super().__init__(account_id=subscription_id, account_name=account_name)
        self._auth_client = auth_client
        self._sample_data: dict[str, Any] | None = None

        if sample_data_path:
            path = Path(sample_data_path)
            with path.open() as fh:
                self._sample_data = json.load(fh)
            logger.info("azure_auditor.sample_mode", path=str(path))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_sample(self) -> dict[str, Any]:
        if self._sample_data is not None:
            return self._sample_data
        raise RuntimeError("No Azure auth client and no sample data provided.")

    def _role_def_map(self) -> dict[str, dict[str, Any]]:
        data = self._get_sample()
        return {rd["id"]: rd for rd in data.get("roleDefinitions", [])}

    def _is_subscription_scope(self, scope: str) -> bool:
        parts = scope.strip("/").split("/")
        return len(parts) == 2 and parts[0] == "subscriptions"

    def _is_cross_tenant(self, assignment: dict[str, Any]) -> bool:
        sub_id = self.account_id or ""
        scope: str = assignment.get("scope", "")
        return sub_id != "" and sub_id not in scope

    # ------------------------------------------------------------------
    # BaseAuditor implementation
    # ------------------------------------------------------------------

    def audit_users(self) -> list[AuditUser]:
        """Return Azure users derived from role assignments with principalType == User."""
        data = self._get_sample()
        role_def_map = self._role_def_map()
        seen: dict[str, AuditUser] = {}

        for assignment in data.get("roleAssignments", []):
            if assignment.get("principalType") != "User":
                continue

            pid = assignment["principalId"]
            role_name = assignment.get("roleDefinitionName", "")
            scope: str = assignment.get("scope", "")

            role_def = role_def_map.get(assignment.get("roleDefinitionId", ""), {})
            actions: list[str] = []
            for perm in role_def.get("permissions", []):
                actions.extend(perm.get("actions", []))

            policy = AuditPolicy(
                policy_id=assignment["roleDefinitionId"],
                policy_name=role_name,
                policy_arn=assignment.get("roleDefinitionId"),
                is_managed=True,
                actions=actions,
                resources=[scope],
                has_wildcard_action="*" in actions,
                has_wildcard_resource=self._is_subscription_scope(scope),
                access_level=_classify_azure_access(actions),
                raw=assignment,
            )

            if pid not in seen:
                created_raw = assignment.get("createdOn")
                created_at: datetime | None = None
                if created_raw:
                    created_at = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))

                seen[pid] = AuditUser(
                    user_id=pid,
                    user_name=assignment.get("principalName", pid),
                    created_at=created_at,
                    mfa_enabled=False,  # Not available via RBAC API
                    attached_policies=[policy],
                    provider=CloudProvider.AZURE,
                    raw=assignment,
                )
            else:
                seen[pid].attached_policies.append(policy)

        users = list(seen.values())
        logger.info("azure_auditor.users_collected", count=len(users))
        return users

    def audit_roles(self) -> list[AuditRole]:
        """Return Azure role definitions as AuditRole objects."""
        data = self._get_sample()
        roles: list[AuditRole] = []

        for rd in data.get("roleDefinitions", []):
            actions: list[str] = []
            for perm in rd.get("permissions", []):
                actions.extend(perm.get("actions", []))

            has_wildcard = "*" in actions

            policy = AuditPolicy(
                policy_id=rd["id"],
                policy_name=rd["roleName"],
                policy_arn=rd["id"],
                is_managed=rd.get("roleType") == "BuiltInRole",
                actions=actions,
                resources=[],
                has_wildcard_action=has_wildcard,
                has_wildcard_resource=False,
                access_level=_classify_azure_access(actions),
                raw=rd,
            )

            roles.append(
                AuditRole(
                    role_id=rd["name"],
                    role_name=rd["roleName"],
                    arn=rd["id"],
                    attached_policies=[policy],
                    inline_policies=[],
                    is_cross_account=False,
                    is_public=has_wildcard,
                    is_service_role=rd.get("roleType") == "BuiltInRole",
                    provider=CloudProvider.AZURE,
                    raw=rd,
                )
            )

        logger.info("azure_auditor.roles_collected", count=len(roles))
        return roles

    def audit_policies(self) -> list[AuditPolicy]:
        """Return custom Azure role definitions as standalone policies."""
        data = self._get_sample()
        policies: list[AuditPolicy] = []

        for rd in data.get("roleDefinitions", []):
            if rd.get("roleType") != "CustomRole":
                continue
            actions: list[str] = []
            for perm in rd.get("permissions", []):
                actions.extend(perm.get("actions", []))

            policies.append(
                AuditPolicy(
                    policy_id=rd["id"],
                    policy_name=rd["roleName"],
                    policy_arn=rd["id"],
                    is_managed=False,
                    actions=actions,
                    resources=[],
                    has_wildcard_action="*" in actions,
                    has_wildcard_resource=False,
                    access_level=_classify_azure_access(actions),
                    raw=rd,
                )
            )

        logger.info("azure_auditor.policies_collected", count=len(policies))
        return policies

    def audit_service_accounts(self) -> list[AuditServiceAccount]:
        data = self._get_sample()
        service_accounts: list[AuditServiceAccount] = []
        role_def_map = self._role_def_map()

        sp_map: dict[str, dict[str, Any]] = {
            sp["id"]: sp for sp in data.get("servicePrincipals", [])
        }

        for assignment in data.get("roleAssignments", []):
            if assignment.get("principalType") != "ServicePrincipal":
                continue

            pid = assignment["principalId"]
            sp = sp_map.get(pid, {})
            role_name = assignment.get("roleDefinitionName", "")
            scope: str = assignment.get("scope", "")

            role_def = role_def_map.get(assignment.get("roleDefinitionId", ""), {})
            actions: list[str] = []
            for perm in role_def.get("permissions", []):
                actions.extend(perm.get("actions", []))

            policy = AuditPolicy(
                policy_id=assignment["roleDefinitionId"],
                policy_name=role_name,
                policy_arn=assignment.get("roleDefinitionId"),
                is_managed=True,
                actions=actions,
                resources=[scope],
                has_wildcard_action="*" in actions,
                has_wildcard_resource=self._is_subscription_scope(scope),
                access_level=_classify_azure_access(actions),
                raw=assignment,
            )

            created_raw = sp.get("createdDateTime") or assignment.get("createdOn")
            created_at: datetime | None = None
            if created_raw:
                created_at = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))

            service_accounts.append(
                AuditServiceAccount(
                    account_id=pid,
                    account_name=assignment.get("principalName", pid),
                    created_at=created_at,
                    attached_policies=[policy],
                    is_service_principal=True,
                    provider=CloudProvider.AZURE,
                    raw={**assignment, "service_principal": sp},
                )
            )

        logger.info("azure_auditor.service_accounts_collected", count=len(service_accounts))
        return service_accounts

    def _provider(self) -> CloudProvider:
        return CloudProvider.AZURE
