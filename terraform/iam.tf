# ------------------------------------------------------------
# IAM — roles con least privilege para cada Lambda
# El mismo patrón que usaste en tu proyecto anterior con ECS,
# pero ahora para funciones Lambda de seguridad.
# ------------------------------------------------------------

# Trust policy reutilizable para Lambda
locals {
  lambda_assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# ------------------------------------------------------------
# Role: isolate_ec2 Lambda
# Permisos: leer SGs, cambiar SG de una instancia, describir instancias
# ------------------------------------------------------------
resource "aws_iam_role" "lambda_isolate_ec2" {
  name               = "${var.project_name}-lambda-isolate-ec2"
  assume_role_policy = local.lambda_assume_role_policy

  tags = { Name = "${var.project_name}-lambda-isolate-ec2" }
}

resource "aws_iam_role_policy" "lambda_isolate_ec2" {
  name = "isolate-ec2-policy"
  role = aws_iam_role.lambda_isolate_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Isolation"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:ModifyInstanceAttribute", # para cambiar el SG
          "ec2:CreateSnapshot",          # snapshot forense antes de aislar
          "ec2:DescribeSnapshots"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Sid      = "S3Reports"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.incident_reports.arn}/*"
      }
    ]
  })
}

# ------------------------------------------------------------
# Role: revoke_credentials Lambda
# Permisos: listar y desactivar access keys de IAM
# ------------------------------------------------------------
resource "aws_iam_role" "lambda_revoke_credentials" {
  name               = "${var.project_name}-lambda-revoke-creds"
  assume_role_policy = local.lambda_assume_role_policy

  tags = { Name = "${var.project_name}-lambda-revoke-creds" }
}

resource "aws_iam_role_policy" "lambda_revoke_credentials" {
  name = "revoke-credentials-policy"
  role = aws_iam_role.lambda_revoke_credentials.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMRevoke"
        Effect = "Allow"
        Action = [
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey", # desactivar la key comprometida
          "iam:GetUser",
          "iam:ListUserTags"
        ]
        Resource = "*"
      },
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Sid      = "S3Reports"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.incident_reports.arn}/*"
      }
    ]
  })
}

# ------------------------------------------------------------
# Role: block_ip Lambda
# Permisos: modificar NACLs y WAF
# ------------------------------------------------------------
resource "aws_iam_role" "lambda_block_ip" {
  name               = "${var.project_name}-lambda-block-ip"
  assume_role_policy = local.lambda_assume_role_policy

  tags = { Name = "${var.project_name}-lambda-block-ip" }
}

resource "aws_iam_role_policy" "lambda_block_ip" {
  name = "block-ip-policy"
  role = aws_iam_role.lambda_block_ip.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "NACLBlock"
        Effect = "Allow"
        Action = [
          "ec2:DescribeNetworkAcls",
          "ec2:CreateNetworkAclEntry",
          "ec2:ReplaceNetworkAclEntry",
          "ec2:DeleteNetworkAclEntry"
        ]
        Resource = "*"
      },
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Sid      = "S3Reports"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.incident_reports.arn}/*"
      }
    ]
  })
}

# ------------------------------------------------------------
# Role: generate_report Lambda
# Permisos: solo leer GuardDuty findings y escribir a S3/SNS
# ------------------------------------------------------------
resource "aws_iam_role" "lambda_generate_report" {
  name               = "${var.project_name}-lambda-generate-report"
  assume_role_policy = local.lambda_assume_role_policy

  tags = { Name = "${var.project_name}-lambda-generate-report" }
}

resource "aws_iam_role_policy" "lambda_generate_report" {
  name = "generate-report-policy"
  role = aws_iam_role.lambda_generate_report.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GuardDutyRead"
        Effect = "Allow"
        Action = [
          "guardduty:ListFindings",
          "guardduty:GetFindings",
          "guardduty:ListDetectors"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3Reports"
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.incident_reports.arn,
          "${aws_s3_bucket.incident_reports.arn}/*"
        ]
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
      }
    ]
  })
}

# ------------------------------------------------------------
# EventBridge necesita permiso para invocar Lambda
# (se completa en Módulo 3 cuando creamos las Lambdas)
# ------------------------------------------------------------
