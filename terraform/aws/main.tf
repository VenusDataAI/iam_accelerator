terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

###############################################################################
# IAM Role — Auditor (least-privilege, read-only IAM)
###############################################################################

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "auditor_assume_role" {
  statement {
    sid     = "AllowAssumeFromTrustedAccount"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.trusted_principal_arns
    }

    dynamic "condition" {
      for_each = var.require_external_id ? [1] : []
      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [var.external_id]
      }
    }
  }
}

resource "aws_iam_role" "iam_auditor" {
  name                 = var.role_name
  description          = "Least-privilege read-only role used by the IAM Accelerator auditor"
  assume_role_policy   = data.aws_iam_policy_document.auditor_assume_role.json
  max_session_duration = 3600

  tags = merge(var.tags, {
    ManagedBy = "terraform"
    Component = "iam-accelerator"
  })
}

###############################################################################
# Inline least-privilege policy — only the permissions the auditor needs
###############################################################################

data "aws_iam_policy_document" "auditor_permissions" {
  statement {
    sid    = "IAMReadOnly"
    effect = "Allow"
    actions = [
      "iam:GenerateCredentialReport",
      "iam:GetAccountAuthorizationDetails",
      "iam:GetAccountPasswordPolicy",
      "iam:GetAccountSummary",
      "iam:GetCredentialReport",
      "iam:GetGroup",
      "iam:GetGroupPolicy",
      "iam:GetLoginProfile",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:GetUser",
      "iam:GetUserPolicy",
      "iam:ListAccessKeys",
      "iam:ListAccountAliases",
      "iam:ListAttachedGroupPolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListEntitiesForPolicy",
      "iam:ListGroupPolicies",
      "iam:ListGroups",
      "iam:ListGroupsForUser",
      "iam:ListInstanceProfiles",
      "iam:ListMFADevices",
      "iam:ListPolicies",
      "iam:ListPolicyVersions",
      "iam:ListRolePolicies",
      "iam:ListRoles",
      "iam:ListSAMLProviders",
      "iam:ListSSHPublicKeys",
      "iam:ListServerCertificates",
      "iam:ListServiceSpecificCredentials",
      "iam:ListUserPolicies",
      "iam:ListUsers",
      "iam:ListVirtualMFADevices",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AccessAnalyzerReadOnly"
    effect = "Allow"
    actions = [
      "access-analyzer:ListAnalyzers",
      "access-analyzer:ListFindings",
      "access-analyzer:GetAnalyzer",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "OrganizationsReadOnly"
    effect = "Allow"
    actions = [
      "organizations:DescribeOrganization",
      "organizations:ListAccounts",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "auditor_inline" {
  name   = "${var.role_name}-permissions"
  role   = aws_iam_role.iam_auditor.id
  policy = data.aws_iam_policy_document.auditor_permissions.json
}

###############################################################################
# Optional: managed policy attachment for SecurityAudit (broad but read-only)
###############################################################################

resource "aws_iam_role_policy_attachment" "security_audit" {
  count      = var.attach_security_audit_policy ? 1 : 0
  role       = aws_iam_role.iam_auditor.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}
