output "honeypot_public_ip" {
  description = "IP pública del honeypot EC2 — usá esta IP en los scripts de simulación"
  value       = aws_instance.honeypot.public_ip
}

output "honeypot_instance_id" {
  description = "Instance ID del honeypot — usado por la Lambda isolate_ec2"
  value       = aws_instance.honeypot.id
}

output "quarantine_sg_id" {
  description = "ID del Security Group de cuarentena — la Lambda isolate_ec2 mueve instancias aquí"
  value       = aws_security_group.quarantine.id
}

output "guardduty_detector_id" {
  description = "ID del detector de GuardDuty — necesario para generate_report Lambda"
  value       = aws_guardduty_detector.main.id
}

output "incident_reports_bucket" {
  description = "Nombre del bucket S3 donde se guardan los reportes de incidentes"
  value       = aws_s3_bucket.incident_reports.bucket
}

output "cloudtrail_logs_bucket" {
  description = "Nombre del bucket S3 donde se guardan los logs de CloudTrail"
  value       = aws_s3_bucket.cloudtrail_logs.bucket
}

output "sns_topic_arn" {
  description = "ARN del topic SNS de alertas — usado por todas las Lambdas"
  value       = aws_sns_topic.security_alerts.arn
}

output "lambda_function_names" {
  description = "Nombres de las Lambdas de remediación (para ver logs en CloudWatch)"
  value = {
    isolate_ec2        = aws_lambda_function.isolate_ec2.function_name
    revoke_credentials = aws_lambda_function.revoke_credentials.function_name
    block_ip           = aws_lambda_function.block_ip.function_name
    generate_report    = aws_lambda_function.generate_report.function_name
  }
}

output "lambda_role_arns" {
  description = "ARNs de los roles IAM de cada Lambda"
  value = {
    isolate_ec2        = aws_iam_role.lambda_isolate_ec2.arn
    revoke_credentials = aws_iam_role.lambda_revoke_credentials.arn
    block_ip           = aws_iam_role.lambda_block_ip.arn
    generate_report    = aws_iam_role.lambda_generate_report.arn
  }
}
