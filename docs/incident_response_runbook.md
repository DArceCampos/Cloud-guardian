# Runbook de Respuesta a Incidentes

Procedimiento para operar el sistema: cómo verificar que la detección y la
remediación funcionan, qué hace cada Lambda, cómo revertir una acción y cómo
investigar un incidente.

---

## 1. Verificar que el sistema está activo

```bash
cd terraform && terraform output    # IDs y nombres de recursos

# GuardDuty habilitado (debe devolver 1 detector)
aws guardduty list-detectors

# Security Hub con standards activos
aws securityhub get-enabled-standards

# Config grabando
aws configservice describe-configuration-recorder-status

# Suscripción de email confirmada (StatusConfirmed = true)
aws sns list-subscriptions
```

Si la suscripción de email figura como `PendingConfirmation`, revisá tu correo y
hacé clic en **Confirm subscription**.

---

## 2. Disparar un incidente de prueba

### Camino rápido (recomendado para validar el pipeline)

```bash
cd attack_simulation && source .venv/bin/activate
python generate_sample_findings.py
```

Genera findings `[SAMPLE]` de cada tipo al instante. EventBridge los captura igual
que los reales.

### Ataques realistas (latencia de GuardDuty: 15 min – varias horas)

```bash
python simulate_s3_enumeration.py --rondas 10      # → Discovery:S3/*
python simulate_port_scan.py --puertos 1-1024      # → Recon:EC2/*
python simulate_credential_exposure.py             # → Recon:IAMUser/*
```

---

## 3. Confirmar que la remediación corrió

```bash
# Findings activos
aws guardduty list-findings --detector-id <DETECTOR_ID>

# Logs de cada Lambda (últimos eventos)
aws logs tail /aws/lambda/cloud-threat-detection-isolate-ec2 --since 15m
aws logs tail /aws/lambda/cloud-threat-detection-revoke-credentials --since 15m
aws logs tail /aws/lambda/cloud-threat-detection-block-ip --since 15m
aws logs tail /aws/lambda/cloud-threat-detection-generate-report --since 15m

# Reportes generados
aws s3 ls s3://<INCIDENT_REPORTS_BUCKET>/reportes/ --recursive

# Descargar un reporte HTML para verlo
aws s3 cp s3://<BUCKET>/reportes/AAAA/MM/DD/<id>.html ./reporte.html && open reporte.html
```

También deberías recibir uno o más **emails de alerta** por SNS.

---

## 4. Qué hace cada acción de remediación

| Lambda | Acción | Reversible |
|---|---|---|
| `isolate_ec2` | Snapshot EBS + mueve la instancia al SG `quarantine` (sin tráfico) | Sí — reasignar el SG original |
| `revoke_credentials` | Desactiva la access key (`Status=Inactive`) | Sí — reactivar la key |
| `block_ip` | Agrega regla DENY en el NACL para la IP `/32` | Sí — borrar la entrada del NACL |
| `generate_report` | Escribe reporte en S3 + alerta SNS | N/A (solo documenta) |

---

## 5. Revertir acciones (después de confirmar falso positivo)

> ⚠️ Revertí solo cuando hayas confirmado que el finding fue un falso positivo o
> una prueba. Documentá siempre el motivo.

### Sacar una instancia de cuarentena

```bash
# Reasignar el Security Group original del honeypot
aws ec2 modify-instance-attribute \
  --instance-id <INSTANCE_ID> \
  --groups <HONEYPOT_SG_ID>
```

### Reactivar una access key

```bash
aws iam update-access-key \
  --user-name <USER> \
  --access-key-id <KEY_ID> \
  --status Active
```

### Desbloquear una IP

```bash
# Buscar el rule number de la entrada DENY
aws ec2 describe-network-acls --network-acl-ids <NACL_ID>

# Borrarla (ingress)
aws ec2 delete-network-acl-entry \
  --network-acl-id <NACL_ID> \
  --rule-number <N> \
  --ingress
```

---

## 6. Investigación forense

1. **Snapshot EBS** — `isolate_ec2` crea snapshots tageados `Purpose=forensic`.
   Montalos en una instancia de análisis aislada:
   ```bash
   aws ec2 describe-snapshots --filters "Name=tag:Purpose,Values=forensic"
   ```
2. **CloudTrail** — reconstruí la cronología de API calls del atacante:
   ```bash
   aws cloudtrail lookup-events --max-results 50
   ```
3. **Reporte del incidente** — el JSON en S3 incluye el finding crudo completo
   (`raw_finding`) con IPs, recurso afectado y descripción.

---

## 7. Limpieza del entorno

```bash
cd terraform && terraform destroy
```

Esto elimina toda la infraestructura. Recordá hacerlo al terminar de probar:
**GuardDuty y Security Hub solo son gratis 30 días.**

Verificá que no quede nada cobrando:

```bash
aws guardduty list-detectors        # vacío
aws ec2 describe-instances --filters "Name=tag:Project,Values=cloud-threat-detection"
```

> Si `simulate_credential_exposure.py` se interrumpió a la mitad, podría quedar un
> usuario IAM `simulated-leaked-cred-*`. Verificá y borralo:
> ```bash
> aws iam list-users --query "Users[?starts_with(UserName, 'simulated-leaked-cred')]"
> ```
