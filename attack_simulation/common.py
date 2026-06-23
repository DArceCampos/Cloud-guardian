"""
Utilidades compartidas por los scripts de simulación de ataques.

IMPORTANTE — Contexto de uso autorizado:
Estos scripts están diseñados para correr ÚNICAMENTE contra tu propia
infraestructura de laboratorio (el honeypot y la cuenta AWS que vos mismo
desplegaste con Terraform). Incluyen guardrails que abortan si detectan que
estás apuntando a recursos que no son tuyos.
"""

import json
import subprocess
import sys
from pathlib import Path

import boto3

# Ruta al directorio de Terraform (../terraform respecto de este archivo)
TERRAFORM_DIR = Path(__file__).resolve().parent.parent / "terraform"


def banner(titulo: str) -> None:
    """Imprime un banner visible para separar fases en la consola."""
    line = "=" * 60
    print(f"\n{line}\n  {titulo}\n{line}")


def get_terraform_outputs() -> dict:
    """
    Lee los outputs del estado de Terraform (honeypot IP, bucket names, etc.).

    Devuelve un dict {nombre_output: valor}. Aborta con un mensaje claro si
    Terraform todavía no fue aplicado (no hay estado).
    """
    if not TERRAFORM_DIR.exists():
        sys.exit(f"[ERROR] No encuentro el directorio terraform en {TERRAFORM_DIR}")

    try:
        result = subprocess.run(
            ["terraform", "output", "-json"],
            cwd=TERRAFORM_DIR,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        sys.exit("[ERROR] terraform no está instalado o no está en el PATH.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"[ERROR] No pude leer los outputs de Terraform:\n{e.stderr}")

    raw = json.loads(result.stdout or "{}")
    if not raw:
        sys.exit(
            "[ERROR] Terraform no tiene outputs todavía.\n"
            "        Corré 'terraform apply' en el directorio terraform/ antes "
            "de simular ataques."
        )

    # terraform output -json envuelve cada valor en {"value": ..., "type": ...}
    return {k: v["value"] for k, v in raw.items()}


def get_account_id(session: boto3.Session | None = None) -> str:
    """Devuelve el Account ID de las credenciales activas."""
    session = session or boto3.Session()
    return session.client("sts").get_caller_identity()["Account"]


def confirmar_laboratorio() -> dict:
    """
    Guardrail principal: confirma que las credenciales activas son las de la
    misma cuenta donde está desplegada la infraestructura de laboratorio.

    Devuelve los outputs de Terraform si todo coincide. Aborta si no.
    """
    outputs = get_terraform_outputs()
    account_id = get_account_id()

    # El nombre del bucket de reportes incluye el account_id del despliegue.
    bucket = outputs.get("incident_reports_bucket", "")
    if account_id not in bucket:
        sys.exit(
            "[ABORTADO] Las credenciales AWS activas NO coinciden con la cuenta "
            "donde desplegaste el laboratorio.\n"
            f"           Cuenta activa: {account_id}\n"
            f"           Bucket de laboratorio: {bucket}\n"
            "           Por seguridad estos scripts solo corren contra tu propio "
            "entorno de pruebas."
        )

    print(f"[OK] Laboratorio confirmado en la cuenta {account_id}.")
    return outputs


def pedir_confirmacion_explicita(accion: str) -> None:
    """Pide al usuario que escriba 'si' para acciones que tocan AWS de verdad."""
    print(f"\n[ATENCION] Estás a punto de: {accion}")
    respuesta = input("    Escribí 'si' para continuar: ").strip().lower()
    if respuesta != "si":
        sys.exit("[CANCELADO] No se ejecutó nada.")
