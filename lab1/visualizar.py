import re
import json
import os
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
import pandas as pd
import numpy as np
from collections import defaultdict
from datetime import datetime

os.makedirs("lab1/graficas", exist_ok=True)

PATRON_SSH = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
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

def cargar_ssh():
    intentos = defaultdict(int)
    with open("lab1/auth.log") as f:
        for linea in f:
            m = PATRON_SSH.search(linea)
            if m:
                intentos[m.group(2)] += 1
    top10 = sorted(intentos.items(), key=lambda x: x[1], reverse=True)[:10]
    return top10

def cargar_web():
    registros = []
    with open("lab1/access.log") as f:
        for linea in f:
            m = PATRON_LOG.search(linea)
            if not m:
                continue
            mf = PATRON_FECHA.match(m.group("fecha"))
            if not mf:
                continue
            dia, mes, anio, hora, minuto, segundo = mf.groups()
            fecha = datetime(int(anio), MESES[mes], int(dia),
                             int(hora), int(minuto), int(segundo))
            registros.append({
                "fecha": fecha,
                "hora": fecha.hour,
                "codigo": int(m.group("codigo"))
            })
    return registros

def grafica_top10_ssh(top10):
    ips = [x[0] for x in top10]
    intentos = [x[1] for x in top10]

    fig, ax = plt.subplots(figsize=(12, 6))
    colores = ["#e74c3c" if v > 50 else "#3498db" for v in intentos]
    bars = ax.barh(ips[::-1], intentos[::-1], color=colores[::-1], edgecolor="white")

    for bar, val in zip(bars, intentos[::-1]):
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2,
                str(val), va="center", fontsize=10, fontweight="bold")

    ax.set_title("Top 10 IPs con más intentos fallidos SSH", fontsize=14, fontweight="bold", pad=15)
    ax.set_xlabel("Número de intentos fallidos", fontsize=11)
    ax.set_ylabel("Dirección IP", fontsize=11)
    ax.axvline(x=50, color="red", linestyle="--", alpha=0.5, label="Umbral alerta (50)")
    ax.legend(fontsize=10)

    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor="#e74c3c", label="Sobre umbral (>50)"),
        Patch(facecolor="#3498db", label="Bajo umbral (≤50)")
    ]
    ax.legend(handles=legend_elements, loc="lower right", fontsize=10)

    plt.tight_layout()
    plt.savefig("lab1/graficas/top10_ssh.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  Guardado: lab1/graficas/top10_ssh.png")

def grafica_timeline_http(registros):
    peticiones_por_hora = defaultdict(int)
    for r in registros:
        peticiones_por_hora[r["hora"]] += 1

    horas = list(range(24))
    conteos = [peticiones_por_hora.get(h, 0) for h in horas]

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(horas, conteos, marker="o", linewidth=2.5,
            color="#2980b9", markersize=6, markerfacecolor="#e74c3c")
    ax.fill_between(horas, conteos, alpha=0.15, color="#2980b9")

    ax.set_title("Peticiones HTTP por hora del día", fontsize=14, fontweight="bold", pad=15)
    ax.set_xlabel("Hora del día (0–23)", fontsize=11)
    ax.set_ylabel("Número de peticiones", fontsize=11)
    ax.set_xticks(horas)
    ax.set_xticklabels([f"{h:02d}:00" for h in horas], rotation=45, fontsize=8)
    ax.grid(True, alpha=0.3)

    pico = max(range(24), key=lambda h: peticiones_por_hora.get(h, 0))
    ax.annotate(f"Pico: {peticiones_por_hora[pico]} req",
                xy=(pico, peticiones_por_hora[pico]),
                xytext=(pico + 1, peticiones_por_hora[pico] + 5),
                arrowprops=dict(arrowstyle="->", color="red"),
                fontsize=9, color="red")

    plt.tight_layout()
    plt.savefig("lab1/graficas/timeline_http.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  Guardado: lab1/graficas/timeline_http.png")

def grafica_heatmap_http(registros):
    codigos_interes = [200, 301, 404, 500]
    matriz = np.zeros((len(codigos_interes), 24))

    for r in registros:
        if r["codigo"] in codigos_interes:
            fila = codigos_interes.index(r["codigo"])
            matriz[fila][r["hora"]] += 1

    df = pd.DataFrame(
        matriz,
        index=[str(c) for c in codigos_interes],
        columns=[f"{h:02d}h" for h in range(24)]
    )

    fig, ax = plt.subplots(figsize=(16, 5))
    sns.heatmap(df, ax=ax, cmap="YlOrRd", linewidths=0.3,
                linecolor="white", annot=True, fmt=".0f",
                annot_kws={"size": 7}, cbar_kws={"label": "Peticiones"})

    ax.set_title("Mapa de calor — Peticiones HTTP por hora y código de respuesta",
                 fontsize=13, fontweight="bold", pad=15)
    ax.set_xlabel("Hora del día", fontsize=11)
    ax.set_ylabel("Código HTTP", fontsize=11)
    ax.tick_params(axis="x", rotation=45)
    ax.tick_params(axis="y", rotation=0)

    plt.tight_layout()
    plt.savefig("lab1/graficas/heatmap_http.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  Guardado: lab1/graficas/heatmap_http.png")

def main():
    print(f"\n{'='*55}")
    print(f"  GENERANDO VISUALIZACIONES")
    print(f"{'='*55}")
    top10 = cargar_ssh()
    registros = cargar_web()
    grafica_top10_ssh(top10)
    grafica_timeline_http(registros)
    grafica_heatmap_http(registros)
    print(f"\n  Todas las gráficas guardadas en lab1/graficas/")
    print(f"{'='*55}\n")

if __name__ == "__main__":
    main()
