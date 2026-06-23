# ------------------------------------------------------------
# EventBridge — routing de eventos GuardDuty → Lambda
# ------------------------------------------------------------

# Bucket S3 para reportes de incidentes (generados por Lambda)
resource "aws_s3_bucket" "incident_reports" {
  bucket        = "${var.project_name}-incident-reports-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Name = "${var.project_name}-incident-reports"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "incident_reports" {
  bucket = aws_s3_bucket.incident_reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Bloquear acceso público a los reportes
resource "aws_s3_bucket_public_access_block" "incident_reports" {
  bucket                  = aws_s3_bucket.incident_reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ------------------------------------------------------------
# SNS — notificaciones a email y Slack
# ------------------------------------------------------------
resource "aws_sns_topic" "security_alerts" {
  name = "${var.project_name}-security-alerts"

  tags = {
    Name = "${var.project_name}-security-alerts"
  }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ------------------------------------------------------------
# EventBridge Rules
# ------------------------------------------------------------

# Regla 1: Cualquier finding de GuardDuty con severidad HIGH (>= 7.0)
resource "aws_cloudwatch_event_rule" "guardduty_high_severity" {
  name        = "${var.project_name}-guardduty-high"
  description = "Captura findings de GuardDuty con severidad alta"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
    }
  })

  tags = {
    Name = "${var.project_name}-guardduty-high"
  }
}

# Regla 2: Findings de severidad MEDIUM (4-7) — respuesta menos agresiva
resource "aws_cloudwatch_event_rule" "guardduty_medium_severity" {
  name        = "${var.project_name}-guardduty-medium"
  description = "Captura findings de GuardDuty con severidad media"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 4, "<", 7] }]
    }
  })

  tags = {
    Name = "${var.project_name}-guardduty-medium"
  }
}

# Regla 3: Cambios de configuración detectados por Config
resource "aws_cloudwatch_event_rule" "config_compliance" {
  name        = "${var.project_name}-config-noncompliant"
  description = "Captura recursos marcados como NON_COMPLIANT por Config"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })

  tags = {
    Name = "${var.project_name}-config-noncompliant"
  }
}

# Los targets (Lambda) y los permisos de invocación se definen en lambdas.tf
# (Módulo 3), una vez que las funciones existen.
