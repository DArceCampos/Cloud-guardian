"""
Lambda: isolate_ec2

Disparada por findings de GuardDuty de severidad alta. Si el finding involucra
una instancia EC2 comprometida:
  1. Toma un snapshot forense de sus volúmenes EBS (evidencia antes de tocar nada).
  2. Mueve la instancia al Security Group de cuarentena (sin ingress ni egress).
  3. Notifica por SNS.

Si el finding NO involucra una instancia, hace no-op (otra Lambda se encargará).

Variables de entorno:
  QUARANTINE_SG_ID  - ID del Security Group de cuarentena
  SNS_TOPIC_ARN     - ARN del topic de alertas
"""

import os

import boto3

ec2 = boto3.client("ec2")
sns = boto3.client("sns")

QUARANTINE_SG_ID = os.environ["QUARANTINE_SG_ID"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]


def _notify(asunto: str, mensaje: str) -> None:
    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=asunto[:100], Message=mensaje)


def _snapshot_volumenes(instance_id: str) -> list[str]:
    """Crea snapshots de todos los volúmenes EBS de la instancia (forense)."""
    desc = ec2.describe_instances(InstanceIds=[instance_id])
    snapshots = []
    for reserva in desc["Reservations"]:
        for inst in reserva["Instances"]:
            for bdm in inst.get("BlockDeviceMappings", []):
                vol_id = bdm.get("Ebs", {}).get("VolumeId")
                if not vol_id:
                    continue
                snap = ec2.create_snapshot(
                    VolumeId=vol_id,
                    Description=f"Forense {instance_id} (auto-remediacion)",
                    TagSpecifications=[
                        {
                            "ResourceType": "snapshot",
                            "Tags": [
                                {"Key": "Purpose", "Value": "forensic"},
                                {"Key": "SourceInstance", "Value": instance_id},
                            ],
                        }
                    ],
                )
                snapshots.append(snap["SnapshotId"])
    return snapshots


def handler(event, context):
    detail = event.get("detail", {})
    resource = detail.get("resource", {})
    instance = resource.get("instanceDetails", {})
    instance_id = instance.get("instanceId")

    # No-op si el finding no es sobre una instancia EC2.
    if not instance_id:
        print("Finding sin instancia EC2; isolate_ec2 no aplica.")
        return {"status": "skipped", "reason": "no instance in finding"}

    finding_type = detail.get("type", "desconocido")
    print(f"Aislando instancia {instance_id} por finding: {finding_type}")

    # 1. Snapshot forense (no bloqueamos la remediación si falla)
    try:
        snaps = _snapshot_volumenes(instance_id)
        print(f"Snapshots forenses creados: {snaps}")
    except Exception as e:  # noqa: BLE001
        snaps = []
        print(f"[!] No pude crear snapshots: {e}")

    # 2. Mover al SG de cuarentena
    ec2.modify_instance_attribute(
        InstanceId=instance_id, Groups=[QUARANTINE_SG_ID]
    )
    print(f"Instancia {instance_id} movida a cuarentena ({QUARANTINE_SG_ID}).")

    # 3. Notificar
    _notify(
        f"[CLOUD-GUARDIAN] Instancia aislada: {instance_id}",
        (
            f"Finding: {finding_type}\n"
            f"Severidad: {detail.get('severity')}\n"
            f"Instancia: {instance_id}\n"
            f"Acción: movida al Security Group de cuarentena {QUARANTINE_SG_ID}\n"
            f"Snapshots forenses: {snaps or 'ninguno'}\n"
        ),
    )

    return {
        "status": "isolated",
        "instance_id": instance_id,
        "snapshots": snaps,
    }
