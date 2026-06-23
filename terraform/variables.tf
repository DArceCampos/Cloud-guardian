variable "region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "project_name" {
  description = "Nombre del proyecto (usado en tags y nombres de recursos)"
  default     = "cloud-threat-detection"
}

variable "environment" {
  description = "Entorno (dev / staging / prod)"
  default     = "dev"
}

variable "honeypot_instance_type" {
  description = "Tipo de instancia EC2 para el honeypot (t2.micro = free tier)"
  default     = "t2.micro"
}

variable "alert_email" {
  description = "Email donde llegan las alertas de incidentes via SNS"
  type        = string
  # Setear en terraform.tfvars o con -var al hacer apply:
  # alert_email = "tu@email.com"
}

variable "slack_webhook_url" {
  description = "Webhook de Slack para alertas (opcional)"
  type        = string
  default     = ""
  sensitive   = true
}
