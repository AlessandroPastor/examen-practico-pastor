import re
import json
from collections import defaultdict
from datetime import datetime

LOG_FILE = "lab1/auth.log"
OUTPUT_FILE = "lab1/reporte_ssh.json"
UMBRAL_ALERTA = 50

def analizar_ssh():
    intentos_por_ip = defaultdict(int)
    total_fallidos = 0

    patron = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
    )

    with open(LOG_FILE, "r") as f:
        for linea in f:
            match = patron.search(linea)
            if match:
                ip = match.group(2)
                intentos_por_ip[ip] += 1
                total_fallidos += 1

    top10 = sorted(intentos_por_ip.items(), key=lambda x: x[1], reverse=True)[:10]

    print(f"\n{'='*55}")
    print(f"  ANÁLISIS DE AUTENTICACIÓN SSH - auth.log")
    print(f"{'='*55}")
    print(f"  Total intentos fallidos: {total_fallidos}")
    print(f"\n  Top 10 IPs con más intentos fallidos:")
    print(f"  {'-'*45}")

    ips_sospechosas = []
    for ip, intentos in top10:
        alerta = intentos > UMBRAL_ALERTA
        estado = "[ALERTA]" if alerta else "[INFO]  "
        print(f"  {estado} IP: {ip:<18} — {intentos} intentos")
        if alerta:
            print(f"  [ALERTA] IP: {ip} — {intentos} intentos fallidos — Posible ataque de fuerza bruta")
        ips_sospechosas.append({
            "ip": ip,
            "intentos": intentos,
            "alerta": alerta
        })

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": total_fallidos,
        "ips_sospechosas": ips_sospechosas
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    print(f"\n  Reporte exportado a: {OUTPUT_FILE}")
    print(f"{'='*55}\n")

if __name__ == "__main__":
    analizar_ssh()
