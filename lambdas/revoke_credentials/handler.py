"""
Lambda: revoke_credentials

Disparada por findings de GuardDuty de severidad alta. Si el finding involucra
una access key de IAM comprometida (ej. UnauthorizedAccess:IAMUser/...), desactiva
esa access key inmediatamente para cortar el acceso del atacante.

Si el finding NO involucra una access key de un usuario IAM, hace no-op.

Variables de entorno:
  SNS_TOPIC_ARN - ARN del topic de alertas
"""

import os

import boto3

iam = boto3.client("iam")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]


def _notify(asunto: str, mensaje: str) -> None:
    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=asunto[:100], Message=mensaje)


def handler(event, context):
    detail = event.get("detail", {})
    key_details = detail.get("resource", {}).get("accessKeyDetails", {})

    access_key_id = key_details.get("accessKeyId")
    user_name = key_details.get("userName")
    user_type = key_details.get("userType")  # "IAMUser", "AssumedRole", "Root"...

    # No-op si no hay access key en el finding.
    if not access_key_id:
        print("Finding sin access key; revoke_credentials no aplica.")
        return {"status": "skipped", "reason": "no access key in finding"}

    finding_type = detail.get("type", "desconocido")

    # Solo podemos desactivar keys de usuarios IAM (no de roles asumidos ni root).
    if user_type != "IAMUser" or not user_name:
        msg = (
            f"Access key {access_key_id} pertenece a '{user_type}', no a un IAMUser. "
            "No se puede desactivar automáticamente; requiere revisión manual."
        )
        print(msg)
        _notify(
            f"[CLOUD-GUARDIAN] Credencial comprometida (revisión manual): {access_key_id}",
            f"Finding: {finding_type}\n{msg}\n",
        )
        return {"status": "manual_review", "access_key_id": access_key_id}

    # Desactivar la access key comprometida.
    iam.update_access_key(
        UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
    )
    print(f"Access key {access_key_id} de '{user_name}' desactivada.")

    _notify(
        f"[CLOUD-GUARDIAN] Access key desactivada: {access_key_id}",
        (
            f"Finding: {finding_type}\n"
            f"Severidad: {detail.get('severity')}\n"
            f"Usuario IAM: {user_name}\n"
            f"Access key: {access_key_id}\n"
            f"Acción: desactivada (Status=Inactive)\n"
        ),
    )

    return {
        "status": "revoked",
        "access_key_id": access_key_id,
        "user_name": user_name,
    }
