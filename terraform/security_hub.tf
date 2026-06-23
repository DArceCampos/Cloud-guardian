# ------------------------------------------------------------
# Security Hub — agregador central de findings
# ------------------------------------------------------------
resource "aws_securityhub_account" "main" {}

# Habilita el standard de AWS Foundational Security
resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

# Habilita CIS AWS Foundations
resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${var.region}::standards/cis-aws-foundations-benchmark/v/1.2.0"
  depends_on    = [aws_securityhub_account.main]
}

# Conecta GuardDuty con Security Hub para centralizar los findings
resource "aws_securityhub_product_subscription" "guardduty" {
  product_arn = "arn:aws:securityhub:${var.region}::product/aws/guardduty"
  depends_on  = [aws_securityhub_account.main]
}
