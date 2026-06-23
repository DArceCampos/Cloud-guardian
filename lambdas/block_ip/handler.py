"""
Lambda: block_ip

Disparada por findings de GuardDuty de severidad alta. Extrae la IP del atacante
del finding y la bloquea agregando una regla DENY en el Network ACL del honeypot.

A nivel de NACL el bloqueo es a nivel de subred (más amplio que un Security Group)
y las reglas DENY se evalúan antes que cualquier ALLOW.

Si el finding no expone una IP remota, hace no-op.

Variables de entorno:
  HONEYPOT_NACL_ID - ID del Network ACL donde agregar la regla DENY
  SNS_TOPIC_ARN    - ARN del topic de alertas
"""

import os

import boto3

ec2 = boto3.client("ec2")
sns = boto3.client("sns")

HONEYPOT_NACL_ID = os.environ["HONEYPOT_NACL_ID"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]


def _notify(asunto: str, mensaje: str) -> None:
    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=asunto[:100], Message=mensaje)


def _extraer_ip(detail: dict) -> str | None:
    """Busca la IP remota en los distintos tipos de acción de un finding."""
    action = detail.get("service", {}).get("action", {})

    for clave in ("networkConnectionAction", "awsApiCallAction"):
        ip = action.get(clave, {}).get("remoteIpDetails", {}).get("ipAddressV4")
        if ip:
            return ip

    # Los findings de port probe traen una lista de sondas.
    for sonda in action.get("portProbeAction", {}).get("portProbeDetails", []):
        ip = sonda.get("remoteIpDetails", {}).get("ipAddressV4")
        if ip:
            return ip

    return None


def _proximo_rule_number(nacl_id: str) -> int:
    """Encuentra el rule number de ingress libre más bajo (a partir de 100)."""
    desc = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
    usados = {
        e["RuleNumber"]
        for e in desc["NetworkAcls"][0]["Entries"]
        if not e["Egress"]
    }
    n = 100
    while n in usados:
        n += 1
    return n


def handler(event, context):
    detail = event.get("detail", {})
    ip = _extraer_ip(detail)

    if not ip:
        print("Finding sin IP remota; block_ip no aplica.")
        return {"status": "skipped", "reason": "no remote IP in finding"}

    finding_type = detail.get("type", "desconocido")
    rule_number = _proximo_rule_number(HONEYPOT_NACL_ID)

    # Regla DENY de ingress para la IP atacante (/32).
    ec2.create_network_acl_entry(
        NetworkAclId=HONEYPOT_NACL_ID,
        RuleNumber=rule_number,
        Protocol="-1",  # todos los protocolos
        RuleAction="deny",
        Egress=False,
        CidrBlock=f"{ip}/32",
    )
    print(f"IP {ip} bloqueada en NACL {HONEYPOT_NACL_ID} (regla {rule_number}).")

    _notify(
        f"[CLOUD-GUARDIAN] IP bloqueada: {ip}",
        (
            f"Finding: {finding_type}\n"
            f"Severidad: {detail.get('severity')}\n"
            f"IP atacante: {ip}\n"
            f"Acción: regla DENY #{rule_number} en NACL {HONEYPOT_NACL_ID}\n"
        ),
    )

    return {"status": "blocked", "ip": ip, "rule_number": rule_number}
