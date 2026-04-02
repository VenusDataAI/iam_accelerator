variable "aws_region" {
  description = "AWS region to deploy the auditor role into"
  type        = string
  default     = "us-east-1"
}

variable "role_name" {
  description = "Name of the IAM auditor role"
  type        = string
  default     = "iam-accelerator-auditor"
}

variable "trusted_principal_arns" {
  description = "List of IAM principal ARNs that are allowed to assume the auditor role"
  type        = list(string)
  # Example: ["arn:aws:iam::123456789012:root"]
}

variable "require_external_id" {
  description = "Whether to enforce an ExternalId condition on the trust policy (recommended for cross-account)"
  type        = bool
  default     = false
}

variable "external_id" {
  description = "The ExternalId value enforced in the trust policy (only used when require_external_id = true)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "attach_security_audit_policy" {
  description = "Attach the AWS-managed SecurityAudit policy in addition to the inline least-privilege policy"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
