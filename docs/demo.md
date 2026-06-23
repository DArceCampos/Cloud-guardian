# Demo paso a paso

Guia visual del despliegue y prueba end-to-end de la plataforma.


---

## 1. Despliegue con Terraform

Desde `terraform/`, ejecutar `terraform apply`. Terraform crea todos los
recursos en AWS (~40 recursos: EC2, GuardDuty, CloudTrail, Security Hub,
Config, EventBridge, Lambdas, S3, SNS, IAM).

```bash
cd terraform
terraform apply
```

---

## 2. Confirmar suscripcion SNS

Despues del apply, AWS envia un email de confirmacion al correo configurado
en `terraform.tfvars`. Hacer clic en "Confirm subscription" para activar
las alertas.

<!-- SCREENSHOT: email de AWS "You have chosen to subscribe to the topic..." con el boton Confirm -->
![1782244085879](image/demo/1782244085879.png)


---

## 3. Verificar servicios activos en AWS

### 3a. GuardDuty — detector activo

Consola AWS > GuardDuty > muestra el detector habilitado, sin findings todavia.


### 3b. EC2 — honeypot corriendo

Consola AWS > EC2 > Instances > `cloud-threat-detection-honeypot` con estado
"Running" y su IP publica.



### 3c. Security Hub — standards habilitados

Consola AWS > Security Hub > Security standards > AWS Foundational Security
Best Practices y CIS AWS Foundations Benchmark habilitados.



### 3d. CloudTrail — trail activo

Consola AWS > CloudTrail > Trails > `cloud-threat-detection-trail` con
logging activo.


### 3e. Lambdas desplegadas

Consola AWS > Lambda > Functions > las 4 funciones del proyecto listadas.



### 3f. EventBridge — reglas de enrutamiento

Consola AWS > EventBridge > Rules > las reglas por severidad HIGH y MEDIUM
con sus targets (Lambdas).



---

## 4. Generar findings de prueba

Desde `attack_simulation/`, inyectar findings de muestra en GuardDuty.
Estos son findings reales marcados con `[SAMPLE]` que EventBridge captura
igual que los genuinos.

```bash
cd attack_simulation
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python generate_sample_findings.py
```

---

## 5. Findings en GuardDuty

Despues de ~1 minuto, la consola de GuardDuty muestra los findings generados
con distintas severidades (HIGH, MEDIUM, LOW) y tipos de amenaza.

![1782244633841](image/demo/1782244633841.png)
---

## 6. Lambdas ejecutadas (CloudWatch Logs)

EventBridge captura los findings de alta y media severidad y dispara las
Lambdas automaticamente. Los logs se ven en CloudWatch.

```bash
aws logs tail /aws/lambda/cloud-threat-detection-generate-report --since 30m | head -20
aws logs tail /aws/lambda/cloud-threat-detection-isolate-ec2 --since 30m | head -20
aws logs tail /aws/lambda/cloud-threat-detection-block-ip --since 30m | head -20
aws logs tail /aws/lambda/cloud-threat-detection-revoke-credentials --since 30m | head -20
```

## 7. Reportes de incidentes en S3

La Lambda `generate_report` sube reportes JSON y HTML al bucket de incidentes,
organizados por fecha.

```bash
aws s3 ls s3://cloud-threat-detection-incident-reports-316502579268/reportes/ --recursive
```

---

## 8. Alertas por email

SNS envia un email por cada incidente con el resumen: severidad, tipo de
finding, recurso afectado y link al reporte en S3.

![1782244460709](image/demo/1782244460709.png)


---

## 9. Remediacion automatica en accion

Para findings de severidad alta, el sistema ejecuta acciones automaticas:

### 9a. Instancia aislada en cuarentena

`isolate_ec2` mueve la instancia comprometida al Security Group de cuarentena
(sin ingress ni egress). Visible en EC2 > Instances > Security tab.



### 9b. IP bloqueada en NACL

`block_ip` agrega una regla DENY en el Network ACL. Visible en VPC > Network
ACLs > Inbound rules.



### 9c. Snapshots forenses

`isolate_ec2` crea snapshots de los volumenes EBS antes de aislar, para
preservar evidencia forense.

```bash
aws ec2 describe-snapshots --filters "Name=tag:Purpose,Values=forensic" \
  --query "Snapshots[].{ID:SnapshotId,Volume:VolumeId,Date:StartTime}" --output table
```

---

## 10. Limpieza

Destruir toda la infraestructura para evitar cargos:

```bash
cd terraform
terraform destroy
```


---

## Resumen del flujo

```
terraform apply              → infraestructura creada
generate_sample_findings.py  → findings inyectados en GuardDuty
EventBridge                  → captura findings por severidad
Lambdas                      → remedian automaticamente
  isolate_ec2                  → snapshot + cuarentena
  revoke_credentials           → desactiva access key
  block_ip                     → DENY en NACL
  generate_report              → JSON/HTML a S3 + alerta SNS
terraform destroy            → limpieza total
```
