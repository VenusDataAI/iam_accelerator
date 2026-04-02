from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"


class AccessLevel(str, Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    UNKNOWN = "unknown"


class AuditPolicy(BaseModel):
    policy_id: str
    policy_name: str
    policy_arn: str | None = None
    is_managed: bool = True
    is_inline: bool = False
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    has_wildcard_action: bool = False
    has_wildcard_resource: bool = False
    access_level: AccessLevel = AccessLevel.UNKNOWN
    raw: dict[str, Any] = Field(default_factory=dict)


class AuditUser(BaseModel):
    user_id: str
    user_name: str
    arn: str | None = None
    created_at: datetime | None = None
    last_activity: datetime | None = None
    mfa_enabled: bool = False
    attached_policies: list[AuditPolicy] = Field(default_factory=list)
    inline_policies: list[AuditPolicy] = Field(default_factory=list)
    access_keys: list[dict[str, Any]] = Field(default_factory=list)
    provider: CloudProvider = CloudProvider.AWS
    raw: dict[str, Any] = Field(default_factory=dict)


class AuditRole(BaseModel):
    role_id: str
    role_name: str
    arn: str | None = None
    created_at: datetime | None = None
    attached_policies: list[AuditPolicy] = Field(default_factory=list)
    inline_policies: list[AuditPolicy] = Field(default_factory=list)
    trust_principals: list[str] = Field(default_factory=list)
    is_cross_account: bool = False
    is_public: bool = False
    is_service_role: bool = False
    provider: CloudProvider = CloudProvider.AWS
    raw: dict[str, Any] = Field(default_factory=dict)


class AuditServiceAccount(BaseModel):
    account_id: str
    account_name: str
    arn: str | None = None
    created_at: datetime | None = None
    attached_policies: list[AuditPolicy] = Field(default_factory=list)
    is_service_principal: bool = True
    provider: CloudProvider = CloudProvider.AZURE
    raw: dict[str, Any] = Field(default_factory=dict)


class AuditResult(BaseModel):
    provider: CloudProvider
    audited_at: datetime = Field(default_factory=datetime.utcnow)
    account_id: str | None = None
    account_name: str | None = None
    users: list[AuditUser] = Field(default_factory=list)
    roles: list[AuditRole] = Field(default_factory=list)
    policies: list[AuditPolicy] = Field(default_factory=list)
    service_accounts: list[AuditServiceAccount] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def total_resources(self) -> int:
        return len(self.users) + len(self.roles) + len(self.policies) + len(self.service_accounts)


class BaseAuditor(ABC):
    def __init__(self, account_id: str | None = None, account_name: str | None = None) -> None:
        self.account_id = account_id
        self.account_name = account_name

    @abstractmethod
    def audit_users(self) -> list[AuditUser]:
        """Collect and normalize IAM users / Azure AD users."""

    @abstractmethod
    def audit_roles(self) -> list[AuditRole]:
        """Collect and normalize IAM roles / Azure RBAC role definitions."""

    @abstractmethod
    def audit_policies(self) -> list[AuditPolicy]:
        """Collect and normalize standalone IAM policies / Azure custom role definitions."""

    @abstractmethod
    def audit_service_accounts(self) -> list[AuditServiceAccount]:
        """Collect and normalize service accounts / Azure service principals."""

    def run(self) -> AuditResult:
        """Execute full audit and return a unified AuditResult."""
        users = self.audit_users()
        roles = self.audit_roles()
        policies = self.audit_policies()
        service_accounts = self.audit_service_accounts()

        return AuditResult(
            provider=self._provider(),
            account_id=self.account_id,
            account_name=self.account_name,
            users=users,
            roles=roles,
            policies=policies,
            service_accounts=service_accounts,
        )

    @abstractmethod
    def _provider(self) -> CloudProvider:
        """Return the cloud provider enum value."""
