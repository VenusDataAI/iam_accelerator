variable "subscription_id" {
  description = "Azure Subscription ID where the auditor role will be created"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the Resource Group used as the assignable scope for the custom role"
  type        = string
}

variable "role_definition_name" {
  description = "Display name for the custom IAM auditor role definition"
  type        = string
  default     = "IAM Accelerator Auditor"
}

variable "auditor_principal_id" {
  description = "Object ID of the service principal, managed identity, or user that should receive the auditor role assignment"
  type        = string
}

variable "role_condition" {
  description = "Optional ABAC condition expression for the role assignment (leave empty to disable)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to the resource group (if created by this module)"
  type        = map(string)
  default     = {}
}
