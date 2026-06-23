# ------------------------------------------------------------
# GuardDuty — detección de amenazas en EC2, IAM, S3
# ------------------------------------------------------------
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true # detecta enumeración y acceso sospechoso a S3
    }
    kubernetes {
      audit_logs {
        enable = false # no usamos EKS en este proyecto
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true # escanea EBS cuando detecta malware en EC2
        }
      }
    }
  }

  tags = {
    Name = "${var.project_name}-guardduty"
  }
}
