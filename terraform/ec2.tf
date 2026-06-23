# ------------------------------------------------------------
# Security Groups
# ------------------------------------------------------------

# SG del honeypot: expuesto intencionalmente para generar eventos en GuardDuty
resource "aws_security_group" "honeypot" {
  name        = "${var.project_name}-honeypot-sg"
  description = "Honeypot EC2 - expuesto para generar eventos GuardDuty"
  vpc_id      = data.aws_vpc.default.id

  # SSH abierto intencionalmente: genera findings de tipo UnauthorizedAccess:EC2/SSHBruteForce
  ingress {
    description = "SSH desde internet (honeypot intencional)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP abierto: genera findings de tipo Recon:EC2/PortProbeUnprotectedPort
  ingress {
    description = "HTTP desde internet (honeypot intencional)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-honeypot-sg"
    Role = "honeypot"
  }
}

# SG de cuarentena: sin ingress, sin egress — aísla instancias comprometidas
# La Lambda isolate_ec2 mueve instancias aquí automáticamente
resource "aws_security_group" "quarantine" {
  name        = "${var.project_name}-quarantine-sg"
  description = "Cuarentena - sin acceso entrante ni saliente"
  vpc_id      = data.aws_vpc.default.id

  # Sin reglas de ingress ni egress: bloqueo total

  tags = {
    Name = "${var.project_name}-quarantine-sg"
    Role = "quarantine"
  }
}

# ------------------------------------------------------------
# EC2 Honeypot
# ------------------------------------------------------------
resource "aws_instance" "honeypot" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = var.honeypot_instance_type
  subnet_id                   = tolist(data.aws_subnets.default.ids)[0]
  vpc_security_group_ids      = [aws_security_group.honeypot.id]
  associate_public_ip_address = true

  # User data: instala utilidades mínimas para generar tráfico detectable
  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y nmap curl wget
    # Genera algo de actividad de red para que GuardDuty tenga tráfico que analizar
    echo "Honeypot inicializado: $(date)" > /tmp/honeypot.log
  EOF

  tags = {
    Name = "${var.project_name}-honeypot"
    Role = "honeypot"
  }
}
