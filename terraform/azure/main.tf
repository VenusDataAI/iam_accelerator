terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

provider "azuread" {}

###############################################################################
# Data sources
###############################################################################

data "azurerm_subscription" "current" {}

data "azurerm_resource_group" "auditor_scope" {
  name = var.resource_group_name
}

###############################################################################
# Custom Reader Role — scoped to the resource group
###############################################################################

resource "azurerm_role_definition" "iam_auditor" {
  name        = var.role_definition_name
  scope       = data.azurerm_resource_group.auditor_scope.id
  description = "Least-privilege custom reader role used by the IAM Accelerator auditor"

  permissions {
    actions = [
      # Azure RBAC
      "Microsoft.Authorization/roleAssignments/read",
      "Microsoft.Authorization/roleDefinitions/read",
      "Microsoft.Authorization/locks/read",
      "Microsoft.Authorization/policyAssignments/read",
      "Microsoft.Authorization/policyDefinitions/read",
      # Azure AD / Graph (read-only)
      "Microsoft.Authorization/*/read",
      # Resource provider metadata
      "Microsoft.Resources/subscriptions/read",
      "Microsoft.Resources/subscriptions/resourceGroups/read",
      "Microsoft.Resources/subscriptions/resourceGroups/resources/read",
      # Security Center / Defender
      "Microsoft.Security/assessments/read",
      "Microsoft.Security/securityStatuses/read",
      "Microsoft.Security/pricings/read",
    ]
    not_actions = []
    data_actions     = []
    not_data_actions = []
  }

  assignable_scopes = [
    data.azurerm_resource_group.auditor_scope.id,
  ]
}

###############################################################################
# Role Assignment — assign the custom role to the auditor service principal
###############################################################################

resource "azurerm_role_assignment" "iam_auditor_assignment" {
  scope              = data.azurerm_resource_group.auditor_scope.id
  role_definition_id = azurerm_role_definition.iam_auditor.role_definition_resource_id
  principal_id       = var.auditor_principal_id

  description = "IAM Accelerator auditor read-only access"

  condition_version = var.role_condition != "" ? "2.0" : null
  condition         = var.role_condition != "" ? var.role_condition : null
}
