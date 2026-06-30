import re
import json
from collections import defaultdict
from datetime import datetime

LOG_FILE = "lab1/access.log"
OUTPUT_FILE = "lab1/reporte_web.json"

PATRON_SQLI = re.compile(
    r"(UNION|SELECT|--|OR\s+1=1|')", re.IGNORECASE
)

PATRON_LOG = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<fecha>[^\]]+)\] '
    r'"(?P<metodo>\S+) (?P<ruta>[^\s"]+) [^"]+" '
    r'(?P<codigo>\d{3}) (?P<bytes>\d+)'
)

PATRON_FECHA = re.compile(
    r'(\d{2})/(\w+)/(\d{4}):(\d{2}):(\d{2}):(\d{2})'
)

MESES = {
    "Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
    "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12
}

def parsear_fecha(fecha_str):
    m = PATRON_FECHA.match(fecha_str)
    if m:
        dia, mes, anio, hora, minuto, segundo = m.groups()
        return datetime(int(anio), MESES[mes], int(dia),
                        int(hora), int(minuto), int(segundo))
    return None

def analizar_web():
    registros = []
    errores_por_ip = defaultdict(lambda: defaultdict(int))
    sqli_detectados = []
    peticiones_ip = defaultdict(list)

    with open(LOG_FILE, "r") as f:
        for linea in f:
            m = PATRON_LOG.search(linea)
            if not m:
                continue
            ip = m.group("ip")
            fecha = parsear_fecha(m.group("fecha"))
            ruta = m.group("ruta")
            codigo = int(m.group("codigo"))

            registros.append({
                "ip": ip, "fecha": fecha,
                "ruta": ruta, "codigo": codigo
            })

            if 400 <= codigo <= 599:
                errores_por_ip[ip][str(codigo)] += 1

            if PATRON_SQLI.search(ruta):
                sqli_detectados.append({
                    "ip": ip,
                    "ruta": ruta,
                    "codigo": codigo,
                    "fecha": fecha.strftime("%Y-%m-%d %H:%M:%S") if fecha else "?"
                })

            if fecha:
                peticiones_ip[ip].append((fecha, ruta))

    escaneos = []
    for ip, peticiones in peticiones_ip.items():
        peticiones.sort(key=lambda x: x[0])
        for i in range(len(peticiones)):
            ventana = [p for p in peticiones[i:]
                       if (p[0] - peticiones[i][0]).total_seconds() <= 60]
            rutas_unicas = set(p[1] for p in ventana)
            if len(rutas_unicas) > 20:
                escaneos.append({
                    "ip": ip,
                    "peticiones_en_60s": len(ventana),
                    "rutas_unicas": len(rutas_unicas),
                    "inicio": peticiones[i][0].strftime("%Y-%m-%d %H:%M:%S")
                })
                break

    print(f"\n{'='*55}")
    print(f"  ANÁLISIS DE ACCESO WEB - access.log")
    print(f"{'='*55}")
    print(f"  Total registros parseados: {len(registros)}")

    print(f"\n  Escaneos de directorios detectados: {len(escaneos)}")
    for e in escaneos[:5]:
        print(f"    IP: {e['ip']} — {e['peticiones_en_60s']} peticiones, "
              f"{e['rutas_unicas']} rutas únicas en 60s desde {e['inicio']}")

    print(f"\n  Intentos de SQL Injection detectados: {len(sqli_detectados)}")
    for s in sqli_detectados[:5]:
        print(f"    IP: {s['ip']} — {s['ruta'][:60]}")

    print(f"\n  IPs con errores 4xx/5xx:")
    errores_lista = []
    for ip, codigos in sorted(errores_por_ip.items(),
                               key=lambda x: sum(x[1].values()), reverse=True)[:10]:
        total = sum(codigos.values())
        print(f"    IP: {ip:<18} — {total} errores {dict(codigos)}")
        errores_lista.append({"ip": ip, "total_errores": total, "por_codigo": dict(codigos)})

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_registros": len(registros),
        "escaneos_detectados": escaneos,
        "sqli_detectados": sqli_detectados,
        "errores_por_ip": errores_lista
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    print(f"\n  Reporte exportado a: {OUTPUT_FILE}")
    print(f"{'='*55}\n")

if __name__ == "__main__":
    analizar_web()
