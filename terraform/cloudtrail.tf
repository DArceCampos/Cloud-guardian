# ------------------------------------------------------------
# CloudTrail — audit log de TODAS las API calls de AWS
# ------------------------------------------------------------

# Bucket S3 donde se guardan los logs de CloudTrail
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "${var.project_name}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true # para poder destruir el bucket en cleanup

  tags = {
    Name = "${var.project_name}-cloudtrail-logs"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Bloquear acceso público al bucket de logs
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Policy que permite a CloudTrail escribir en el bucket
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true  # captura IAM, STS, etc.
  is_multi_region_trail         = false # single region = gratis
  enable_log_file_validation    = true

  # Eventos de gestión (CreateUser, PutBucketPolicy, etc.)
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    # También loggea acceso a objetos S3 específicos
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"] # todos los buckets
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]

  tags = {
    Name = "${var.project_name}-trail"
  }
}
