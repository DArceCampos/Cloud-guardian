"""
Lambda: generate_report

Disparada por TODOS los findings (alta y media severidad). Documenta el incidente:
  1. Genera un reporte estructurado en JSON.
  2. Genera una versión HTML legible.
  3. Sube ambos al bucket de reportes en S3.
  4. Manda un resumen por SNS.

A diferencia de las otras Lambdas, esta no remedia: solo deja constancia. Es la
capa de "reporting" del proyecto.

Variables de entorno:
  REPORTS_BUCKET - bucket S3 donde se guardan los reportes
  SNS_TOPIC_ARN  - ARN del topic de alertas
"""

import datetime as dt
import html
import json
import os

import boto3

s3 = boto3.client("s3")
sns = boto3.client("sns")

REPORTS_BUCKET = os.environ["REPORTS_BUCKET"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]


def _severidad_label(sev) -> str:
    try:
        sev = float(sev)
    except (TypeError, ValueError):
        return "DESCONOCIDA"
    if sev >= 7:
        return "ALTA"
    if sev >= 4:
        return "MEDIA"
    return "BAJA"


def _render_html(datos: dict) -> str:
    e = lambda v: html.escape(str(v))  # noqa: E731
    return f"""<!DOCTYPE html>
<html lang="es">
<head><meta charset="utf-8"><title>Incidente {e(datos['finding_id'])}</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 760px; margin: 2rem auto; color: #1a1a1a; }}
  h1 {{ border-bottom: 3px solid #d33; padding-bottom: .3rem; }}
  .sev-ALTA {{ color: #d33; font-weight: bold; }}
  .sev-MEDIA {{ color: #e69500; font-weight: bold; }}
  .sev-BAJA {{ color: #2a7; font-weight: bold; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #ddd; }}
  th {{ width: 200px; color: #555; }}
</style></head>
<body>
  <h1>Reporte de Incidente</h1>
  <table>
    <tr><th>Severidad</th><td class="sev-{e(datos['severidad_label'])}">{e(datos['severidad_label'])} ({e(datos['severidad'])})</td></tr>
    <tr><th>Tipo de finding</th><td>{e(datos['tipo'])}</td></tr>
    <tr><th>Finding ID</th><td>{e(datos['finding_id'])}</td></tr>
    <tr><th>Recurso afectado</th><td>{e(datos['recurso'])}</td></tr>
    <tr><th>IP atacante</th><td>{e(datos['ip_atacante'])}</td></tr>
    <tr><th>Región</th><td>{e(datos['region'])}</td></tr>
    <tr><th>Detectado</th><td>{e(datos['detectado'])}</td></tr>
    <tr><th>Reporte generado</th><td>{e(datos['generado'])}</td></tr>
  </table>
  <h2>Descripción</h2>
  <p>{e(datos['descripcion'])}</p>
</body></html>"""


def handler(event, context):
    detail = event.get("detail", {})
    service = detail.get("service", {})
    action = service.get("action", {})

    # Extraer IP remota si la hay (mismo patrón que block_ip).
    ip = (
        action.get("networkConnectionAction", {})
        .get("remoteIpDetails", {})
        .get("ipAddressV4")
        or action.get("awsApiCallAction", {})
        .get("remoteIpDetails", {})
        .get("ipAddressV4")
        or "n/a"
    )

    resource = detail.get("resource", {})
    recurso = (
        resource.get("instanceDetails", {}).get("instanceId")
        or resource.get("accessKeyDetails", {}).get("accessKeyId")
        or resource.get("resourceType")
        or "n/a"
    )

    ahora = dt.datetime.now(dt.timezone.utc)
    datos = {
        "finding_id": detail.get("id", "n/a"),
        "tipo": detail.get("type", "n/a"),
        "severidad": detail.get("severity", "n/a"),
        "severidad_label": _severidad_label(detail.get("severity")),
        "recurso": recurso,
        "ip_atacante": ip,
        "region": detail.get("region", event.get("region", "n/a")),
        "descripcion": detail.get("description", "Sin descripción."),
        "detectado": service.get("eventFirstSeen", "n/a"),
        "generado": ahora.isoformat(),
    }

    # Clave S3: reportes/AAAA/MM/DD/<finding_id>.{json,html}
    prefijo = f"reportes/{ahora:%Y/%m/%d}/{datos['finding_id']}"

    s3.put_object(
        Bucket=REPORTS_BUCKET,
        Key=f"{prefijo}.json",
        Body=json.dumps({**datos, "raw_finding": detail}, indent=2, default=str),
        ContentType="application/json",
    )
    s3.put_object(
        Bucket=REPORTS_BUCKET,
        Key=f"{prefijo}.html",
        Body=_render_html(datos),
        ContentType="text/html",
    )
    print(f"Reporte guardado en s3://{REPORTS_BUCKET}/{prefijo}.(json|html)")

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[CLOUD-GUARDIAN] Incidente {datos['severidad_label']}: {datos['tipo']}"[:100],
        Message=(
            f"Severidad: {datos['severidad_label']} ({datos['severidad']})\n"
            f"Tipo: {datos['tipo']}\n"
            f"Recurso: {datos['recurso']}\n"
            f"IP atacante: {datos['ip_atacante']}\n"
            f"Reporte: s3://{REPORTS_BUCKET}/{prefijo}.html\n"
        ),
    )

    return {"status": "reported", "report_key": f"{prefijo}.json"}
