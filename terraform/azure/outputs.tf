output "role_definition_id" {
  description = "ID of the custom IAM auditor role definition"
  value       = azurerm_role_definition.iam_auditor.id
}

output "role_definition_resource_id" {
  description = "Azure resource ID of the custom role definition (used for role assignments)"
  value       = azurerm_role_definition.iam_auditor.role_definition_resource_id
}

output "role_assignment_id" {
  description = "ID of the role assignment that grants the auditor principal access"
  value       = azurerm_role_assignment.iam_auditor_assignment.id
}

output "scope_resource_group_id" {
  description = "Resource group ID used as the scope for the auditor role"
  value       = data.azurerm_resource_group.auditor_scope.id
}

output "subscription_id" {
  description = "Subscription ID where the resources were deployed"
  value       = data.azurerm_subscription.current.subscription_id
}
