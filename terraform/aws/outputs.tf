output "auditor_role_arn" {
  description = "ARN of the IAM auditor role"
  value       = aws_iam_role.iam_auditor.arn
}

output "auditor_role_name" {
  description = "Name of the IAM auditor role"
  value       = aws_iam_role.iam_auditor.name
}

output "auditor_role_unique_id" {
  description = "Unique ID of the IAM auditor role"
  value       = aws_iam_role.iam_auditor.unique_id
}

output "trusted_account_id" {
  description = "Current AWS account ID where the role was created"
  value       = data.aws_caller_identity.current.account_id
}
