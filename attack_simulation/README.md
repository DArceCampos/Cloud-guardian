# Módulo 2 — Attack Simulation

Scripts en Python que simulan ataques reales contra **tu propia** infraestructura
de laboratorio para generar eventos en GuardDuty y CloudTrail. Esos eventos son
los que, en el Módulo 3, disparan las Lambdas de auto-remediación.

> **Uso autorizado únicamente.** Estos scripts están pensados para correr
> contra el honeypot y la cuenta AWS que vos mismo desplegaste con Terraform.
> Incluyen guardrails (`common.confirmar_laboratorio`) que abortan si las
> credenciales activas no coinciden con la cuenta del laboratorio. No los uses
> contra infraestructura que no te pertenece.

## Requisitos previos

1. Haber hecho `terraform apply` en `../terraform/` (los scripts leen sus outputs).
2. Credenciales AWS configuradas (`aws configure`).
3. Dependencias de Python:

```bash
cd attack_simulation
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Los scripts

| Script | Ataque simulado | Genera |
|---|---|---|
| `simulate_s3_enumeration.py` | Enumeración agresiva de buckets S3 | `Discovery:S3/*` |
| `simulate_port_scan.py` | Port scan TCP contra el honeypot | `Recon:EC2/*` |
| `simulate_credential_exposure.py` | Credenciales filtradas usadas para recon IAM | `Recon:IAMUser/*` |
| `generate_sample_findings.py` | **Inyecta findings de muestra al instante** | todos los tipos `[SAMPLE]` |

Todos piden una confirmación explícita (`si`) antes de tocar AWS.

## Sobre la latencia de GuardDuty (importante)

Los 3 scripts de ataque generan tráfico/API calls **reales**, pero GuardDuty
puede tardar de **15 minutos a varias horas** en emitir un finding, y algunos
no se disparan desde una IP residencial (necesitan que la fuente esté en su
threat-intel, o un baseline de comportamiento normal).

**Para iterar sobre las Lambdas del Módulo 3 sin esperar, usá
`generate_sample_findings.py`:** inyecta findings de ejemplo de cada tipo al
instante. Son findings reales que EventBridge captura igual que los genuinos.

```bash
# Camino rápido para probar el pipeline end-to-end:
python generate_sample_findings.py

# Ataques realistas (dejá correr y revisá GuardDuty más tarde):
python simulate_s3_enumeration.py --rondas 10
python simulate_port_scan.py --puertos 1-1024
python simulate_credential_exposure.py
```

## Cómo verificar que generaron eventos

```bash
# Findings actuales en GuardDuty
python generate_sample_findings.py --listar

# O directo por CLI
aws guardduty list-findings --detector-id <ID>

# Eventos en CloudTrail (últimos)
aws cloudtrail lookup-events --max-results 10
```

## Limpieza

- `simulate_credential_exposure.py` **borra solo** el usuario IAM temporal que
  crea (incluso si falla, vía `finally`).
- Los findings de muestra desaparecen solos o se pueden archivar desde la consola.
- El resto de los scripts no crean recursos persistentes.
