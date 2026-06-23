#!/usr/bin/env python3
"""
Simulación de ataque: PORT SCAN contra el honeypot

Qué hace un atacante real:
  Antes de explotar una máquina, escanea qué puertos tiene abiertos para
  encontrar servicios vulnerables (SSH, HTTP, bases de datos, etc.).

Qué genera en AWS:
  • Tráfico entrante hacia la EC2 honeypot (expuesta a propósito en 22 y 80).
  • GuardDuty EC2 puede generar 'Recon:EC2/PortProbeUnprotectedPort' cuando el
    sondeo proviene de fuentes que su threat-intel considera maliciosas. Desde
    tu IP residencial puede no dispararlo: por eso, para probar el pipeline al
    instante, está generate_sample_findings.py.

Este scanner usa sockets de Python (no requiere nmap). Es un TCP connect scan
simple, suficiente para generar el tráfico hacia el honeypot.

Uso:
  python simulate_port_scan.py [--puertos 1-1024] [--timeout 0.5]
"""

import argparse
import socket
import time

from common import banner, confirmar_laboratorio, pedir_confirmacion_explicita


def parse_rango_puertos(spec: str) -> range:
    """Convierte '1-1024' o '22-80' en un range de puertos."""
    if "-" in spec:
        ini, fin = spec.split("-", 1)
        return range(int(ini), int(fin) + 1)
    p = int(spec)
    return range(p, p + 1)


def escanear(ip: str, puertos: range, timeout: float) -> None:
    banner(f"Escaneando {ip}  (puertos {puertos.start}-{puertos.stop - 1})")
    abiertos = []
    inicio = time.time()

    for puerto in puertos:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            # connect_ex devuelve 0 si el puerto está abierto.
            if sock.connect_ex((ip, puerto)) == 0:
                abiertos.append(puerto)
                print(f"  [ABIERTO] puerto {puerto}")
        except OSError:
            pass
        finally:
            sock.close()

    dur = time.time() - inicio
    banner("RESULTADO")
    print(f"Puertos abiertos: {abiertos or 'ninguno'}")
    print(f"Escaneados {len(puertos)} puertos en {dur:.1f}s.")
    print(
        "\nEsto generó tráfico entrante hacia el honeypot. En GuardDuty buscá\n"
        "findings 'Recon:EC2/*' (puede tardar o no dispararse desde tu IP).\n"
        "Para probar el pipeline YA: generate_sample_findings.py"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Port scan contra el honeypot.")
    parser.add_argument(
        "--puertos",
        default="1-1024",
        help="Rango de puertos, ej. '1-1024' o '22-443' (default: 1-1024).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Timeout por puerto en segundos (default: 0.5).",
    )
    args = parser.parse_args()

    banner("SIMULACIÓN: PORT SCAN")
    outputs = confirmar_laboratorio()

    ip = outputs.get("honeypot_public_ip")
    if not ip:
        raise SystemExit("[ERROR] No encontré 'honeypot_public_ip' en los outputs.")

    print(f"[+] Objetivo: honeypot en {ip} (tu propia infraestructura)")
    puertos = parse_rango_puertos(args.puertos)
    pedir_confirmacion_explicita(f"escanear {len(puertos)} puertos de {ip}")
    escanear(ip, puertos, args.timeout)


if __name__ == "__main__":
    main()
