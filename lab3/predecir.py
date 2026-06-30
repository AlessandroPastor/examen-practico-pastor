import sys
import joblib
import pandas as pd
import numpy as np

if len(sys.argv) < 2:
    print("Uso: python predecir.py <archivo_csv>")
    sys.exit(1)

CSV_FILE = sys.argv[1]

model = joblib.load('lab3/modelo_anomalias.pkl')
scaler = joblib.load('lab3/scaler.pkl')

df = pd.read_csv(CSV_FILE)
df['ratio_bytes'] = df['bytes_sent'] / (df['bytes_recv'] + 1)
df['bytes_por_segundo'] = (df['bytes_sent'] + df['bytes_recv']) / (df['duration_sec'] + 0.001)

features = ['bytes_sent', 'bytes_recv', 'duration_sec', 'packets',
            'dst_port', 'ratio_bytes', 'bytes_por_segundo']

X = scaler.transform(df[features])
scores = model.decision_function(X)
predicciones = model.predict(X)

df['anomaly_score'] = scores
df['prediccion'] = predicciones
anomalias = df[df['prediccion'] == -1]

print(f"\n{'='*55}")
print(f"  PREDICCIÓN — {CSV_FILE}")
print(f"{'='*55}")
print(f"  Total registros  : {len(df)}")
print(f"  Anomalías        : {len(anomalias)}")
print(f"\n  Registros anómalos (top 10):")
print(f"  {'-'*50}")
for _, row in anomalias.head(10).iterrows():
    print(f"  IP: {row['src_ip']:<18} Puerto: {int(row['dst_port']):<6} Score: {row['anomaly_score']:.4f}")
print(f"{'='*55}\n")
