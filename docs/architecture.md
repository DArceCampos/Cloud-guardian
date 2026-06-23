# Arquitectura

## Vista general

El sistema tiene cuatro capas: **simulación**, **detección**, **respuesta** y
**reporting**. Un ataque genera un finding en GuardDuty, EventBridge lo enruta
según severidad, las Lambdas remedian y todo queda documentado.

```mermaid
flowchart TD
    subgraph SIM["Attack Simulation (Python)"]
        A1[simulate_s3_enumeration]
        A2[simulate_port_scan]
        A3[simulate_credential_exposure]
        A4[generate_sample_findings]
    end

    subgraph DET["Detection Layer"]
        GD[GuardDuty]
        CT[CloudTrail]
        CFG[AWS Config]
        SH[Security Hub]
    end

    subgraph RESP["Response Layer"]
        EB{EventBridge<br/>rules por severidad}
        L1[isolate_ec2]
        L2[revoke_credentials]
        L3[block_ip]
        L4[generate_report]
    end

    subgraph REP["Reporting Layer"]
        S3[(S3<br/>reportes JSON/HTML)]
        SNS[SNS → Email/Slack]
    end

    A1 & A2 & A3 --> GD
    A4 -.findings de muestra.-> GD
    GD --> CT
    GD --> EB
    CFG --> SH
    GD --> SH

    EB -->|severidad ALTA ≥7| L1 & L2 & L3 & L4
    EB -->|severidad MEDIA 4-7| L4

    L1 -->|snapshot + cuarentena| SNS
    L2 -->|key Inactive| SNS
    L3 -->|DENY en NACL| SNS
    L4 --> S3
    L4 --> SNS
```

## Flujo de un incidente (severidad alta)

```mermaid
sequenceDiagram
    participant Atk as Atacante (simulado)
    participant GD as GuardDuty
    participant EB as EventBridge
    participant Lx as Lambdas de remediación
    participant AWS as Recursos AWS
    participant Rep as S3 + SNS

    Atk->>GD: Actividad anómala (recon, brute force, exfil)
    GD->>EB: GuardDuty Finding (severity ≥ 7)
    EB->>Lx: Invoca isolate_ec2, revoke_credentials, block_ip, generate_report
    Note over Lx: Cada Lambda se auto-selecciona<br/>según el tipo de recurso
    Lx->>AWS: Aísla instancia / desactiva key / bloquea IP
    Lx->>Rep: Reporte JSON+HTML a S3 y alerta por email
    Rep-->>Atk: Acceso cortado, incidente documentado
```

## Componentes clave

### Detección
- **GuardDuty** — motor de detección de amenazas (EC2, IAM, S3). Emite findings
  con un score de severidad 1–8.8.
- **CloudTrail** — log de auditoría de todas las API calls (un trail single-region
  = gratis). Encriptado y con validación de integridad.
- **AWS Config** — detecta misconfiguraciones con reglas managed (SSH abierto,
  S3 público, EC2 sin IMDSv2, IAM sin MFA).
- **Security Hub** — agrega findings de GuardDuty y los standards AWS Foundational
  + CIS en un solo lugar.

### Respuesta
- **EventBridge** — dos reglas por severidad (alta ≥7, media 4–7) más una de
  Config. Enruta a las Lambdas.
- **Lambdas** — Python 3.12, cada una con un rol IAM least-privilege (definidos en
  `terraform/iam.tf`). Empaquetadas y conectadas en `terraform/lambdas.tf`.

### Reporting
- **S3** — bucket privado y encriptado con los reportes (`reportes/AAAA/MM/DD/<id>.{json,html}`).
- **SNS** — topic con suscripción de email (y opcionalmente Slack).

## Decisiones de diseño

1. **Auto-selección en vez de dispatcher.** La regla de alta severidad dispara las
   4 Lambdas; cada una hace no-op si el finding no le corresponde. Funciones
   independientes, fáciles de testear por separado, sin un punto único de fallo.

2. **Snapshot antes de aislar.** `isolate_ec2` preserva evidencia forense antes de
   mover la instancia a cuarentena. Si el snapshot falla, igual aísla (la seguridad
   no se bloquea por la evidencia).

3. **Honeypot intencionalmente expuesto.** La EC2 abre SSH/HTTP al mundo a propósito
   para generar findings. Por eso `tfsec`/`Checkov` corren en `soft_fail`: esos
   hallazgos son esperados.

4. **VPC default reutilizada.** Para mantenerlo en free tier y simple, no se crea
   VPC propia. En producción usarías una VPC dedicada con subnets privadas.

## Generar el PNG (opcional)

El diagrama Mermaid se renderiza directo en GitHub. Si querés un `architecture.png`
para presentaciones:

```bash
npx @mermaid-js/mermaid-cli -i docs/architecture.md -o docs/architecture.png
```
