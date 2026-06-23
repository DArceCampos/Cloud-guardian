#!/usr/bin/env python3
"""
Simulación de ataque: ENUMERACIÓN AGRESIVA DE S3

Qué hace un atacante real:
  Cuando alguien roba credenciales, lo primero que hace es "mapear" la cuenta.
  En S3 eso significa listar todos los buckets y, por cada uno, intentar leer
  su política, ACL, ubicación, y listar objetos — muy rápido y en volumen.

Qué genera en AWS:
  • Eventos en CloudTrail: ListBuckets, GetBucketPolicy, GetBucketAcl, ListObjects
  • Con el tiempo y un baseline, GuardDuty S3 Protection puede marcar
    'Discovery:S3/AnomalousBehavior'.

Uso:
  python simulate_s3_enumeration.py [--rondas N]
"""

import argparse
import time

import boto3
from botocore.exceptions import ClientError

from common import banner, confirmar_laboratorio, pedir_confirmacion_explicita


def enumerar_s3(rondas: int) -> None:
    s3 = boto3.client("s3")

    banner("FASE 1 — Listando todos los buckets (reconnaissance)")
    try:
        buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    except ClientError as e:
        print(f"[ERROR] No pude listar buckets: {e}")
        return

    print(f"[+] Descubiertos {len(buckets)} buckets:")
    for b in buckets:
        print(f"      - {b}")

    banner("FASE 2 — Sondeando cada bucket (políticas, ACLs, contenido)")
    # Llamadas de descubrimiento típicas de un atacante mapeando permisos.
    sondas = [
        ("GetBucketPolicy", lambda n: s3.get_bucket_policy(Bucket=n)),
        ("GetBucketAcl", lambda n: s3.get_bucket_acl(Bucket=n)),
        ("GetBucketLocation", lambda n: s3.get_bucket_location(Bucket=n)),
        ("GetBucketEncryption", lambda n: s3.get_bucket_encryption(Bucket=n)),
        ("ListObjectsV2", lambda n: s3.list_objects_v2(Bucket=n, MaxKeys=50)),
    ]

    for ronda in range(1, rondas + 1):
        print(f"\n--- Ronda {ronda}/{rondas} ---")
        for nombre_bucket in buckets:
            for api, fn in sondas:
                try:
                    fn(nombre_bucket)
                    print(f"  [+] {api:<22} {nombre_bucket}")
                except ClientError as e:
                    # AccessDenied / NoSuchBucketPolicy son esperables y útiles:
                    # el atacante igual aprende qué está y qué no está protegido.
                    code = e.response["Error"]["Code"]
                    print(f"  [-] {api:<22} {nombre_bucket}  ({code})")
        # Sin pausa entre rondas: el volumen rápido es lo que se ve anómalo.

    banner("LISTO")
    print(
        "Enumeración completada. Revisá:\n"
        "  • CloudTrail → eventos GetBucketPolicy/ListObjects en ráfaga\n"
        "  • GuardDuty  → puede tardar; mirá findings 'Discovery:S3/*'\n"
        "  • Para probar el pipeline YA, usá generate_sample_findings.py"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Simula enumeración agresiva de S3.")
    parser.add_argument(
        "--rondas",
        type=int,
        default=5,
        help="Cuántas veces repetir el sondeo de todos los buckets (default: 5).",
    )
    args = parser.parse_args()

    banner("SIMULACIÓN: ENUMERACIÓN DE S3")
    confirmar_laboratorio()
    pedir_confirmacion_explicita(
        f"hacer {args.rondas} rondas de enumeración S3 sobre TU cuenta"
    )
    enumerar_s3(args.rondas)


if __name__ == "__main__":
    main()
