# 🛡️ Cloud Threat Detection & Auto-Remediation Platform

Sistema que **detecta ataques reales en AWS, los analiza y responde
automáticamente** sin intervención humana. Todo definido como código (IaC).

Simulás ataques contra tu propia infraestructura, GuardDuty los detecta,
EventBridge enruta el evento, una Lambda clasifica la severidad y ejecuta la
remediación (aislar, revocar, bloquear), y queda un reporte en S3 + alerta por
email/Slack.

```
Ataque simulado
      ↓
GuardDuty detecta anomalía
      ↓
EventBridge captura el evento
      ↓
Lambda analiza + clasifica severidad
      ↓
Auto-remediación (aislar EC2 · revocar keys · bloquear IP)
      ↓
Reporte en S3 (JSON + HTML) + alerta por SNS
```

> Diagrama completo y flujos en [`docs/architecture.md`](docs/architecture.md).
> Procedimiento de respuesta en [`docs/incident_response_runbook.md`](docs/incident_response_runbook.md).

---

## 📁 Estructura del repo

```
Cloud-guardian/
├── terraform/                  # Módulo 1 — Infraestructura
│   ├── main.tf                 #   provider + data sources
│   ├── ec2.tf                  #   honeypot + security groups
│   ├── guardduty.tf            #   GuardDuty
│   ├── cloudtrail.tf           #   CloudTrail + bucket de logs
│   ├── security_hub.tf         #   Security Hub
│   ├── config.tf               #   AWS Config + reglas
│   ├── eventbridge.tf          #   EventBridge + SNS + bucket de reportes
│   ├── iam.tf                  #   roles least-privilege de las Lambdas
│   ├── lambdas.tf              #   empaqueta y conecta las Lambdas (Módulo 3)
│   ├── variables.tf / outputs.tf
│   └── terraform.tfvars.example
├── lambdas/                    # Módulo 3 — Auto-remediación
│   ├── isolate_ec2/            #   aísla EC2 comprometida (+ snapshot forense)
│   ├── revoke_credentials/     #   desactiva access key comprometida
│   ├── block_ip/               #   bloquea IP del atacante en el NACL
│   └── generate_report/        #   reporte JSON/HTML a S3 + alerta SNS
├── attack_simulation/          # Módulo 2 — Simulación de ataques
│   ├── simulate_s3_enumeration.py
│   ├── simulate_port_scan.py
│   ├── simulate_credential_exposure.py
│   └── generate_sample_findings.py   # inyecta findings de prueba al instante
├── .github/workflows/          # Módulo 4 — CI/CD
│   ├── security_scan.yml       #   fmt + validate + tfsec + Checkov (cada PR)
│   └── deploy.yml              #   apply manual (opt-in)
└── docs/
    ├── architecture.md
    └── incident_response_runbook.md
```

---

## ✅ Requisitos previos

| Herramienta | Para qué | Instalar (macOS) |
|---|---|---|
| Terraform ≥ 1.3 | Desplegar la infraestructura | `brew install hashicorp/tap/terraform` |
| AWS CLI v2 | Credenciales + verificación | `brew install awscli` |
| Python ≥ 3.10 | Scripts de simulación | ya viene en macOS |

Configurá tus credenciales (quedan en `~/.aws/`, **nunca** en el repo):

```bash
aws configure          # Access Key, Secret, region=us-east-1, output=json
aws sts get-caller-identity   # verificá que funcionan
```

> 🔐 Este proyecto **no usa archivos `.env` con keys**. Terraform y boto3 leen
> las credenciales del entorno estándar de AWS. Nunca pongas keys en archivos
> `.tf` ni en el repo.

---

## 🚀 Desplegar (Opción A — apply manual local)

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # editá tu email adentro
terraform init
terraform plan                                  # revisá qué se va a crear (gratis)
terraform apply                                 # crea los recursos (confirmá con 'yes')
```

Después del apply:

```bash
terraform output           # IP del honeypot, buckets, nombres de Lambdas, etc.
```

Revisá tu email: SNS te manda un **"Confirm subscription"** — confirmalo para
recibir las alertas.

---

## 🧪 Probar de punta a punta

La forma más rápida de validar todo el pipeline (sin esperar la latencia real de
GuardDuty) es inyectar findings de muestra:

```bash
cd attack_simulation
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python generate_sample_findings.py   # genera findings [SAMPLE] al instante
```

EventBridge captura esos findings → dispara las Lambdas → vas a ver:
- Reportes en el bucket `*-incident-reports-*` (JSON + HTML)
- Emails de alerta por SNS
- Logs de ejecución en CloudWatch (`/aws/lambda/cloud-threat-detection-*`)

Para ataques **realistas** (generan tráfico/API real; GuardDuty puede tardar):

```bash
python simulate_s3_enumeration.py --rondas 10
python simulate_port_scan.py --puertos 1-1024
python simulate_credential_exposure.py
```

Detalle de cada script en [`attack_simulation/README.md`](attack_simulation/README.md).

---

## 💰 Costos y free tier

Pensado para correr en **free tier**. Costo real estimado: **$0–$3/mes** si lo
usás con moderación.

| Servicio | Free tier |
|---|---|
| GuardDuty | 30 días gratis |
| Security Hub | 30 días gratis |
| CloudTrail | 1 trail gratis (permanente) |
| Lambda | 1M invocaciones/mes |
| S3 | 5 GB |
| SNS | 1M notificaciones |
| EventBridge | 14M eventos/mes |
| EC2 t2.micro | 750 hrs/mes |
| **AWS Config** | ⚠️ cobra por recurso registrado (~$1–3/mes desde el día 1) |

> **GuardDuty y Security Hub son gratis solo 30 días.** No dejes el lab corriendo
> olvidado. Cuando termines de probar:

```bash
cd terraform && terraform destroy
```

---

## 🔄 CI/CD

- **`security_scan.yml`** corre en cada PR: `terraform fmt/validate` + `tfsec` +
  `Checkov` + compilación de los handlers Python. No necesita credenciales AWS.
- **`deploy.yml`** es **manual (opt-in)**. Como el estado es local (Opción A), el
  deploy real se hace con `terraform apply` desde tu máquina. Para habilitar el
  deploy automático en CI hay que migrar el estado a un backend S3 remoto (Opción
  B — ver más abajo).

### Opción B — estado remoto (futuro)

Para deploy automático desde CI necesitás estado compartido:

1. Crear (una sola vez) un bucket S3 + tabla DynamoDB para el lock.
2. Agregar un bloque `backend "s3"` en `terraform/main.tf`.
3. `terraform init -migrate-state`.
4. Cargar los secrets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `ALERT_EMAIL`
   en GitHub y reactivar el trigger `push` en `deploy.yml`.

---

## 🏗️ Cómo funciona la respuesta automática

Las reglas de EventBridge clasifican por severidad:

| Severidad | Acción |
|---|---|
| **ALTA** (≥ 7) | `isolate_ec2` + `revoke_credentials` + `block_ip` + `generate_report` |
| **MEDIA** (4–7) | solo `generate_report` (documenta, sin remediar) |

Cada Lambda **se auto-selecciona** según el tipo de recurso del finding: la regla
de alta severidad dispara las 4, pero cada una hace no-op si el finding no le
corresponde (una instancia EC2 → solo aísla; una access key → solo revoca; etc.).

---

## ⚠️ Aviso de uso

Los scripts de `attack_simulation/` simulan ataques **contra tu propia
infraestructura de laboratorio**. Incluyen guardrails que abortan si las
credenciales activas no son de la cuenta del lab. Es un proyecto educativo de
seguridad defensiva — no lo uses contra infraestructura que no te pertenece.
