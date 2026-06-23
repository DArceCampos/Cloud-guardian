# ------------------------------------------------------------
# Lambdas de auto-remediación (Módulo 3)
# Empaqueta cada función, la despliega con su rol IAM (definido en iam.tf)
# y la conecta a las reglas de EventBridge (definidas en eventbridge.tf).
# ------------------------------------------------------------

# NACL del honeypot — block_ip agrega reglas DENY acá.
# En la VPC default, las subnets usan el NACL default.
data "aws_network_acls" "honeypot" {
  vpc_id = data.aws_vpc.default.id
}

locals {
  honeypot_nacl_id = tolist(data.aws_network_acls.honeypot.ids)[0]
  lambdas_dir      = "${path.module}/../lambdas"
}

# ------------------------------------------------------------
# Empaquetado (zip) de cada Lambda
# ------------------------------------------------------------
data "archive_file" "isolate_ec2" {
  type        = "zip"
  source_dir  = "${local.lambdas_dir}/isolate_ec2"
  output_path = "${path.module}/.builds/isolate_ec2.zip"
}

data "archive_file" "revoke_credentials" {
  type        = "zip"
  source_dir  = "${local.lambdas_dir}/revoke_credentials"
  output_path = "${path.module}/.builds/revoke_credentials.zip"
}

data "archive_file" "block_ip" {
  type        = "zip"
  source_dir  = "${local.lambdas_dir}/block_ip"
  output_path = "${path.module}/.builds/block_ip.zip"
}

data "archive_file" "generate_report" {
  type        = "zip"
  source_dir  = "${local.lambdas_dir}/generate_report"
  output_path = "${path.module}/.builds/generate_report.zip"
}

# ------------------------------------------------------------
# Funciones Lambda
# ------------------------------------------------------------
resource "aws_lambda_function" "isolate_ec2" {
  function_name    = "${var.project_name}-isolate-ec2"
  role             = aws_iam_role.lambda_isolate_ec2.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.isolate_ec2.output_path
  source_code_hash = data.archive_file.isolate_ec2.output_base64sha256

  environment {
    variables = {
      QUARANTINE_SG_ID = aws_security_group.quarantine.id
      SNS_TOPIC_ARN    = aws_sns_topic.security_alerts.arn
    }
  }

  tags = { Name = "${var.project_name}-isolate-ec2" }
}

resource "aws_lambda_function" "revoke_credentials" {
  function_name    = "${var.project_name}-revoke-credentials"
  role             = aws_iam_role.lambda_revoke_credentials.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.revoke_credentials.output_path
  source_code_hash = data.archive_file.revoke_credentials.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }

  tags = { Name = "${var.project_name}-revoke-credentials" }
}

resource "aws_lambda_function" "block_ip" {
  function_name    = "${var.project_name}-block-ip"
  role             = aws_iam_role.lambda_block_ip.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.block_ip.output_path
  source_code_hash = data.archive_file.block_ip.output_base64sha256

  environment {
    variables = {
      HONEYPOT_NACL_ID = local.honeypot_nacl_id
      SNS_TOPIC_ARN    = aws_sns_topic.security_alerts.arn
    }
  }

  tags = { Name = "${var.project_name}-block-ip" }
}

resource "aws_lambda_function" "generate_report" {
  function_name    = "${var.project_name}-generate-report"
  role             = aws_iam_role.lambda_generate_report.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.generate_report.output_path
  source_code_hash = data.archive_file.generate_report.output_base64sha256

  environment {
    variables = {
      REPORTS_BUCKET = aws_s3_bucket.incident_reports.bucket
      SNS_TOPIC_ARN  = aws_sns_topic.security_alerts.arn
    }
  }

  tags = { Name = "${var.project_name}-generate-report" }
}

# ------------------------------------------------------------
# Targets de EventBridge — qué Lambda dispara cada regla
# ------------------------------------------------------------

# Severidad ALTA → respuesta agresiva: las 4 Lambdas.
# Cada una se auto-selecciona según el tipo de recurso del finding.
resource "aws_cloudwatch_event_target" "high_isolate" {
  rule = aws_cloudwatch_event_rule.guardduty_high_severity.name
  arn  = aws_lambda_function.isolate_ec2.arn
}

resource "aws_cloudwatch_event_target" "high_revoke" {
  rule = aws_cloudwatch_event_rule.guardduty_high_severity.name
  arn  = aws_lambda_function.revoke_credentials.arn
}

resource "aws_cloudwatch_event_target" "high_block" {
  rule = aws_cloudwatch_event_rule.guardduty_high_severity.name
  arn  = aws_lambda_function.block_ip.arn
}

resource "aws_cloudwatch_event_target" "high_report" {
  rule = aws_cloudwatch_event_rule.guardduty_high_severity.name
  arn  = aws_lambda_function.generate_report.arn
}

# Severidad MEDIA → solo documentar, sin remediación automática.
resource "aws_cloudwatch_event_target" "medium_report" {
  rule = aws_cloudwatch_event_rule.guardduty_medium_severity.name
  arn  = aws_lambda_function.generate_report.arn
}

# ------------------------------------------------------------
# Permisos para que EventBridge invoque cada Lambda
# ------------------------------------------------------------
resource "aws_lambda_permission" "high_isolate" {
  statement_id  = "AllowEventBridgeHighIsolate"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.isolate_ec2.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_high_severity.arn
}

resource "aws_lambda_permission" "high_revoke" {
  statement_id  = "AllowEventBridgeHighRevoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.revoke_credentials.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_high_severity.arn
}

resource "aws_lambda_permission" "high_block" {
  statement_id  = "AllowEventBridgeHighBlock"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.block_ip.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_high_severity.arn
}

resource "aws_lambda_permission" "high_report" {
  statement_id  = "AllowEventBridgeHighReport"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.generate_report.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_high_severity.arn
}

resource "aws_lambda_permission" "medium_report" {
  statement_id  = "AllowEventBridgeMediumReport"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.generate_report.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_medium_severity.arn
}
