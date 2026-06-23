# ------------------------------------------------------------
# AWS Config — detección de misconfiguraciones
# ------------------------------------------------------------

# Config necesita un recorder + delivery channel antes de las reglas
resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project_name}-recorder"
  role_arn = aws_iam_role.config_recorder.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true # IAM users, roles, policies
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.project_name}-delivery"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.bucket # reutilizamos el bucket

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# IAM Role para Config Recorder
resource "aws_iam_role" "config_recorder" {
  name = "${var.project_name}-config-recorder"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_recorder" {
  role       = aws_iam_role.config_recorder.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Policy para que Config pueda escribir en S3
resource "aws_iam_role_policy" "config_s3" {
  name = "config-s3-access"
  role = aws_iam_role.config_recorder.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:PutObject", "s3:GetBucketAcl"]
      Resource = [
        aws_s3_bucket.cloudtrail_logs.arn,
        "${aws_s3_bucket.cloudtrail_logs.arn}/*"
      ]
    }]
  })
}

# ------------------------------------------------------------
# Config Rules — detectan misconfiguraciones comunes
# ------------------------------------------------------------

# Detecta Security Groups con SSH (22) abierto al mundo
resource "aws_config_config_rule" "restricted_ssh" {
  name        = "${var.project_name}-restricted-ssh"
  description = "Verifica que no haya SGs con SSH 0.0.0.0/0"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Detecta buckets S3 con acceso público
resource "aws_config_config_rule" "s3_no_public_access" {
  name        = "${var.project_name}-s3-no-public"
  description = "Verifica que los buckets S3 bloqueen acceso público"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Detecta instancias EC2 sin IMDSv2 (vulnerabilidad SSRF)
resource "aws_config_config_rule" "ec2_imdsv2" {
  name        = "${var.project_name}-ec2-imdsv2"
  description = "Verifica que las instancias EC2 usen IMDSv2"

  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Detecta usuarios IAM con acceso de consola pero sin MFA
resource "aws_config_config_rule" "iam_mfa" {
  name        = "${var.project_name}-iam-mfa"
  description = "Verifica que los usuarios IAM con acceso a consola tengan MFA"

  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}
