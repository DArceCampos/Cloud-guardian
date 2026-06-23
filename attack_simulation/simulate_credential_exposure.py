#!/usr/bin/env python3
"""
Simulación de ataque: CREDENCIALES FILTRADAS USADAS PARA RECONNAISSANCE

Qué hace un atacante real:
  Consigue un par de access keys (las encontró en un repo público, en un log,
  en un .env subido por error) y las usa para "mapear" la cuenta: listar
  usuarios, roles, políticas, instancias, buckets... antes de escalar.

Qué hace este script (de forma SEGURA y autocontenida):
  1. Crea un usuario IAM descartable (simulated-leaked-cred-<timestamp>).
  2. Le genera access keys (esto simula la credencial "filtrada").
  3. Con ESAS keys hace una ráfaga de llamadas de reconnaissance.
  4. Limpia TODO al final (borra keys y usuario), incluso si algo falla.

Qué genera en AWS:
  • Eventos en CloudTrail: CreateUser, ListUsers, ListRoles, GetAccountAuthorizationDetails...
  • GuardDuty puede generar findings 'Recon:IAMUser/*' o
    'Discovery:IAMUser/AnomalousBehavior'.

Uso:
  python simulate_credential_exposure.py
"""

import time

import boto3
from botocore.exceptions import ClientError

from common import banner, confirmar_laboratorio, pedir_confirmacion_explicita

# Política administrada de solo-lectura: deja que el recon "funcione" sin
# poder modificar nada (least privilege incluso para la simulación).
READONLY_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


def crear_usuario_y_keys(iam) -> tuple[str, dict]:
    nombre = f"simulated-leaked-cred-{int(time.time())}"
    banner(f"FASE 1 — Creando credencial 'filtrada': {nombre}")

    iam.create_user(
        UserName=nombre,
        Tags=[{"Key": "Purpose", "Value": "attack-simulation"}],
    )
    iam.attach_user_policy(UserName=nombre, PolicyArn=READONLY_POLICY_ARN)
    key = iam.create_access_key(UserName=nombre)["AccessKey"]
    print(f"[+] Usuario creado y access key generada: {key['AccessKeyId']}")

    # IAM es eventualmente consistente: dale un momento a que la key propague.
    print("[-] Esperando a que la credencial propague (10s)...")
    time.sleep(10)
    return nombre, key


def reconnaissance_con_keys(key: dict) -> None:
    banner("FASE 2 — Reconnaissance usando la credencial filtrada")

    # Sesión NUEVA usando exclusivamente las keys "robadas".
    atacante = boto3.Session(
        aws_access_key_id=key["AccessKeyId"],
        aws_secret_access_key=key["SecretAccessKey"],
    )
    iam_a = atacante.client("iam")
    sts_a = atacante.client("sts")
    ec2_a = atacante.client("ec2")
    s3_a = atacante.client("s3")

    sondas = [
        ("Quién soy", lambda: sts_a.get_caller_identity()),
        ("Listar usuarios IAM", lambda: iam_a.list_users()),
        ("Listar roles IAM", lambda: iam_a.list_roles()),
        ("Listar políticas", lambda: iam_a.list_policies(Scope="Local")),
        ("Volcar autorizaciones", lambda: iam_a.get_account_authorization_details()),
        ("Listar instancias EC2", lambda: ec2_a.describe_instances()),
        ("Listar security groups", lambda: ec2_a.describe_security_groups()),
        ("Listar buckets S3", lambda: s3_a.list_buckets()),
    ]

    # Varias pasadas para que el volumen se vea claramente anómalo.
    for ronda in range(1, 4):
        print(f"\n--- Pasada de recon {ronda}/3 ---")
        for descripcion, fn in sondas:
            try:
                fn()
                print(f"  [+] {descripcion}")
            except ClientError as e:
                print(f"  [-] {descripcion}  ({e.response['Error']['Code']})")


def limpiar(iam, nombre: str, key_id: str | None) -> None:
    banner("FASE 3 — Limpieza (borrando la credencial simulada)")
    try:
        if key_id:
            iam.delete_access_key(UserName=nombre, AccessKeyId=key_id)
            print(f"[+] Access key {key_id} eliminada.")
        iam.detach_user_policy(UserName=nombre, PolicyArn=READONLY_POLICY_ARN)
        iam.delete_user(UserName=nombre)
        print(f"[+] Usuario {nombre} eliminado.")
    except ClientError as e:
        print(
            f"[!] No pude limpiar del todo ({e.response['Error']['Code']}).\n"
            f"    Revisá manualmente el usuario IAM '{nombre}'."
        )


def main() -> None:
    banner("SIMULACIÓN: CREDENCIALES FILTRADAS")
    confirmar_laboratorio()
    pedir_confirmacion_explicita(
        "crear un usuario IAM temporal, usarlo para recon y luego borrarlo"
    )

    iam = boto3.client("iam")
    nombre = None
    key = None
    try:
        nombre, key = crear_usuario_y_keys(iam)
        reconnaissance_con_keys(key)
    finally:
        if nombre:
            limpiar(iam, nombre, key["AccessKeyId"] if key else None)

    banner("LISTO")
    print(
        "Reconnaissance completado y credencial eliminada.\n"
        "  • CloudTrail → ráfaga de ListUsers/ListRoles/GetAccountAuthorizationDetails\n"
        "  • GuardDuty  → buscá findings 'Recon:IAMUser/*' (puede tardar)\n"
        "  • Para probar el pipeline YA: generate_sample_findings.py"
    )


if __name__ == "__main__":
    main()
