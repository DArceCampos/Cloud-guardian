#!/usr/bin/env python3
"""
Generador de FINDINGS DE MUESTRA de GuardDuty.

Por qué existe:
  Los ataques reales (los otros 3 scripts) generan tráfico genuino, pero
  GuardDuty puede tardar de 15 minutos a varias horas en emitir un finding —
  y algunos no se disparan desde una IP residencial.

  Para probar de punta a punta el pipeline EventBridge → Lambda → remediación
  del Módulo 3, GuardDuty ofrece 'create-sample-findings': inyecta findings de
  ejemplo de CADA tipo al instante. Son findings reales en la consola, marcados
  con el prefijo '[SAMPLE]'.

Esta es la forma recomendada de iterar sobre las Lambdas sin esperar.

Uso:
  python generate_sample_findings.py            # genera findings de muestra
  python generate_sample_findings.py --listar   # lista los tipos disponibles
"""

import argparse

import boto3
from botocore.exceptions import ClientError

from common import banner, confirmar_laboratorio


def get_detector_id(gd) -> str:
    detectores = gd.list_detectors().get("DetectorIds", [])
    if not detectores:
        raise SystemExit(
            "[ERROR] No hay detector de GuardDuty. ¿Corriste 'terraform apply'?"
        )
    return detectores[0]


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera findings de muestra.")
    parser.add_argument(
        "--listar",
        action="store_true",
        help="Solo lista los tipos de finding disponibles, sin generar nada.",
    )
    args = parser.parse_args()

    banner("GUARDDUTY — FINDINGS DE MUESTRA")
    confirmar_laboratorio()

    gd = boto3.client("guardduty")
    detector_id = get_detector_id(gd)
    print(f"[+] Detector: {detector_id}")

    if args.listar:
        banner("Findings ACTUALES en el detector")
        ids = gd.list_findings(DetectorId=detector_id).get("FindingIds", [])
        if not ids:
            print("  (sin findings todavía)")
        else:
            detalle = gd.get_findings(DetectorId=detector_id, FindingIds=ids[:50])
            for f in detalle.get("Findings", []):
                print(f"  [{f['Severity']:>4}] {f['Type']}  ({f['Id'][:12]}…)")
        print(
            "\nTipos de amenaza que cubre GuardDuty:\n"
            " https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html"
        )
        return

    try:
        gd.create_sample_findings(DetectorId=detector_id)
    except ClientError as e:
        raise SystemExit(f"[ERROR] {e.response['Error']['Code']}: {e}")

    banner("LISTO")
    print(
        "Findings de muestra generados (uno por cada tipo, prefijo '[SAMPLE]').\n\n"
        "Verlos:\n"
        "  • Consola → GuardDuty → Findings\n"
        "  • CLI     → aws guardduty list-findings --detector-id "
        f"{detector_id}\n\n"
        "En el Módulo 3, EventBridge va a capturar estos findings y disparar\n"
        "las Lambdas de remediación. Este es el camino para iterar rápido."
    )


if __name__ == "__main__":
    main()
