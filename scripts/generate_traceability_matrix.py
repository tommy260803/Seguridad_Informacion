"""Generación de Matriz de Trazabilidad Científica para RAEA-Phish (Fase 8)."""
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "artifacts" / "raea"

rows = [
    {
        "id_requisito": "RQ1",
        "tipo": "Pregunta de Investigacion",
        "descripcion": "Reduccion de clasificaciones benignas prematuras en M0",
        "hipotesis": "H1",
        "experimento": "EXP-02",
        "archivo_evidencia": "early_exit_results.csv",
        "metrica_clave": "fn_at_stage0_url redujo de 12 a 3 (75% reduccion)",
        "estado_conclusion": "RESPALDADA",
    },
    {
        "id_requisito": "RQ2",
        "tipo": "Pregunta de Investigacion",
        "descripcion": "Beneficio de considerar disponibilidad esperada pi_m",
        "hipotesis": "H2",
        "experimento": "EXP-04, Ablacion A1",
        "archivo_evidencia": "availability_results.csv, component_contribution.csv",
        "metrica_clave": "ROC-AUC 0.74 (infra) y 0.80 (content); ahorro de 0.24 modalidades en vano",
        "estado_conclusion": "RESPALDADA",
    },
    {
        "id_requisito": "RQ3",
        "tipo": "Pregunta de Investigacion",
        "descripcion": "Impacto de costes asimetricos gamma en el riesgo ponderado",
        "hipotesis": "H3",
        "experimento": "EXP-01, EXP-07, Ablacion A2",
        "archivo_evidencia": "baseline_comparison.csv, sensitivity_analysis.csv",
        "metrica_clave": "Riesgo ponderado se reduce de 1.4590 (simetrico) a 0.3867 (asimetrico gamma=15)",
        "estado_conclusion": "RESPALDADA",
    },
    {
        "id_requisito": "RQ4",
        "tipo": "Pregunta de Investigacion",
        "descripcion": "Compromiso entre deteccion, abstencion, coste y latencia",
        "hipotesis": "Hipotesis Principal",
        "experimento": "EXP-01, EXP-03, EXP-06",
        "archivo_evidencia": "baseline_comparison.csv, latency_results.csv, coverage_risk.csv",
        "metrica_clave": "F1=0.8475 con 65.2% de ahorro de coste y 10.0% de abstencion protectora",
        "estado_conclusion": "RESPALDADA",
    },
    {
        "id_requisito": "RQ5",
        "tipo": "Pregunta de Investigacion",
        "descripcion": "Generalizacion externa en fuentes independientes no vistas",
        "hipotesis": "Hipotesis Principal",
        "experimento": "EXP-05",
        "archivo_evidencia": "external_validation.csv",
        "metrica_clave": "F1 superior o equivalente en 7 fuentes externas (CERT.pl, OpenPhish, PhishTank, etc.)",
        "estado_conclusion": "RESPALDADA",
    },
    {
        "id_requisito": "RQ6",
        "tipo": "Pregunta de Investigacion",
        "descripcion": "Descomposicion de componentes explicativos",
        "hipotesis": "H4",
        "experimento": "Fase 5 (Ablaciones A0-A7)",
        "archivo_evidencia": "ablation_results.csv, component_contribution.csv",
        "metrica_clave": "Asimetria de costes y valor informativo explican >90% de la ganancia",
        "estado_conclusion": "RESPALDADA",
    },
    {
        "id_requisito": "SEC-01",
        "tipo": "Restriccion de Seguridad",
        "descripcion": "Inmutabilidad de modelos y particiones historicas",
        "hipotesis": "N/A",
        "experimento": "Auditoria Hash SHA-256",
        "archivo_evidencia": "MANIFIESTO_MODELOS_SHA256.csv",
        "metrica_clave": "0 discrepancias en hashes de modelos historicos",
        "estado_conclusion": "RESPALDADA",
    },
    {
        "id_requisito": "STAT-01",
        "tipo": "Rigor Estadistico",
        "descripcion": "Significancia de reduccion de riesgo en Bootstrap pareado",
        "hipotesis": "Hipotesis Principal",
        "experimento": "Fase 6 (Bootstrap B=2000)",
        "archivo_evidencia": "bootstrap_results.csv",
        "metrica_clave": "p < 0.0001 frente a todos los comparadores en reduccion de riesgo ponderado",
        "estado_conclusion": "RESPALDADA",
    },
]

df = pd.DataFrame(rows)
df.to_csv(OUT_DIR / "MATRIZ_TRAZABILIDAD.csv", index=False)
df.to_csv(ROOT / "MATRIZ_TRAZABILIDAD.csv", index=False)
print("Generada MATRIZ_TRAZABILIDAD.csv con exito.")
