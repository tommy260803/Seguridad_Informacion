"""
research/sensitivity_m0.py: Experimento riguroso de sensibilidad al tamaño de entrenamiento de M0
con separación estricta tripartita en desarrollo:
1. Conjunto de entrenamiento base (D_train): fracciones 25%, 50%, 75%, 100% de N=123,341.
2. Conjunto de calibración (D_cal): subconjunto de validación (N=12,801) para cal.fit().
3. Conjunto de evaluación y selección (D_val_eval): subconjunto de validación fuera de muestra (N=13,629)
   con cero solapamiento de dominios respecto a D_cal, para cal.predict_proba().
4. Test canónico (N=26,430): congelado e intacto (cero test leakage).
"""
from __future__ import annotations

import time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import (
    brier_score_loss,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    log_loss,
)

from phishguard_ml.features import FEATURE_PROFILES, UrlFeatureContext, extract_url_features
from research.workspace import find_data_file, get_experiments_dir

def run_m0_sensitivity(workspace_root: Path | None = None) -> pd.DataFrame:
    print("=" * 75)
    print("[research.sensitivity_m0] SENSIBILIDAD DE M0 CON SEPARACIÓN TRIPARTITA ESTRICTA")
    print("=" * 75)

    samples_path = find_data_file("samples.csv", ["processed/0.1.0"])
    splits_path = find_data_file("conventional.csv", ["processed/0.1.0/splits"])

    print(f"  + Leyendo samples.csv ({samples_path}) y conventional.csv ({splits_path})...")
    df_samples = pd.read_csv(samples_path)
    df_splits = pd.read_csv(splits_path)
    df = pd.merge(df_samples, df_splits, on="sample_id")

    train_df = df[df["partition"] == "train"].copy().reset_index(drop=True)
    val_full = df[df["partition"].isin(["val", "validation"])].copy().reset_index(drop=True)
    test_df = df[df["partition"] == "test"].copy().reset_index(drop=True)

    print(f"  + Total entrenamiento elegible: N={len(train_df):,} ({train_df['registered_domain'].nunique():,} dominios)")
    print(f"  + Total validación completa:   N={len(val_full):,} ({val_full['registered_domain'].nunique():,} dominios)")
    print(f"  + Total test reservado:        N={len(test_df):,} (CONGELADO - CERO USO)")

    # Separación tripartita de validación agrupada por dominio registrado (cero leakage de dominio)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=42)
    cal_idx, eval_idx = next(gss.split(val_full, groups=val_full["registered_domain"]))
    val_cal = val_full.iloc[cal_idx].copy().reset_index(drop=True)
    val_eval = val_full.iloc[eval_idx].copy().reset_index(drop=True)

    domain_overlap_cal_eval = set(val_cal["registered_domain"]).intersection(set(val_eval["registered_domain"]))
    print(f"  + Partición D_cal (ajuste calibrador):      N={len(val_cal):,} ({val_cal['registered_domain'].nunique():,} dominios)")
    print(f"  + Partición D_val_eval (evaluación fuera): N={len(val_eval):,} ({val_eval['registered_domain'].nunique():,} dominios)")
    print(f"  + Solapamiento de dominios D_cal vs D_val_eval: {len(domain_overlap_cal_eval)} (VERIFICADO 0)")

    auth_features = FEATURE_PROFILES["authority_only"]

    def extract_features_labels(sub_df: pd.DataFrame, label_name: str) -> tuple[np.ndarray, np.ndarray]:
        t0 = time.time()
        X_l, y_l = [], []
        for _, row in sub_df.iterrows():
            ctx = UrlFeatureContext(canonical_url=row["canonical_url"], registered_domain=str(row["registered_domain"]))
            fdict = extract_url_features(ctx)
            X_l.append([fdict.get(k, 0.0) for k in auth_features])
            y_l.append(1 if row["label"] == "phishing" else 0)
        arr_X = np.asarray(X_l, dtype=np.float32)
        arr_y = np.asarray(y_l, dtype=np.int32)
        print(f"    - Extracción {label_name} ({len(sub_df):,} obs) en {time.time()-t0:.2f}s")
        return arr_X, arr_y

    print("\n  + Extrayendo características léxicas...")
    X_cal, y_cal = extract_features_labels(val_cal, "D_cal")
    X_eval, y_eval = extract_features_labels(val_eval, "D_val_eval")
    X_train_full, y_train_full = extract_features_labels(train_df, "D_train_full")

    fractions = [0.25, 0.50, 0.75, 1.00]
    seeds = [42, 123, 999]
    results = []

    print("\n  + Ejecutando barrido de sensibilidad x semillas...")
    best_brier = float("inf")
    best_model = None

    for frac in fractions:
        n_sub = int(len(train_df) * frac)
        for seed in seeds:
            rng = np.random.default_rng(seed)
            if frac < 1.0:
                idx = rng.choice(len(train_df), size=n_sub, replace=False)
                X_tr = X_train_full[idx]
                y_tr = y_train_full[idx]
                sub_domains = train_df.iloc[idx]["registered_domain"].nunique()
            else:
                X_tr = X_train_full
                y_tr = y_train_full
                sub_domains = train_df["registered_domain"].nunique()

            t_fit_start = time.time()
            base = HistGradientBoostingClassifier(max_iter=100, random_state=seed)
            base.fit(X_tr, y_tr)

            # CALIBRACIÓN ESTRICTA SOBRE D_cal
            cal = CalibratedClassifierCV(estimator=FrozenEstimator(base), method="isotonic")
            cal.fit(X_cal, y_cal)
            train_sec = time.time() - t_fit_start

            # EVALUACIÓN INDEPENDIENTE FUERA DE MUESTRA SOBRE D_val_eval
            probs_eval = cal.predict_proba(X_eval)[:, 1]
            preds_eval = (probs_eval >= 0.5).astype(int)

            f1 = float(f1_score(y_eval, preds_eval))
            rec = float(recall_score(y_eval, preds_eval))
            prec = float(precision_score(y_eval, preds_eval))
            tn = int(np.sum((preds_eval == 0) & (y_eval == 0)))
            fp = int(np.sum((preds_eval == 1) & (y_eval == 0)))
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            brier = float(brier_score_loss(y_eval, probs_eval))
            auc = float(roc_auc_score(y_eval, probs_eval))
            logloss = float(log_loss(y_eval, np.clip(probs_eval, 1e-6, 1.0 - 1e-6)))

            results.append({
                "fraction": frac,
                "fraction_pct": f"{int(frac*100)}%",
                "n_samples_train": n_sub,
                "n_domains_train": sub_domains,
                "n_samples_cal": len(val_cal),
                "n_samples_val_eval": len(val_eval),
                "seed": seed,
                "f1_val_eval": f1,
                "recall_val_eval": rec,
                "precision_val_eval": prec,
                "fpr_val_eval": fpr,
                "brier_score_val_eval": brier,
                "roc_auc_val_eval": auc,
                "log_loss_val_eval": logloss,
                "train_seconds": train_sec,
                "evaluation_mode": "Strictly_Out_Of_Sample_Disjoint_Domains",
            })

            if frac == 1.0 and seed == 42:
                best_model = cal
                best_brier = brier

    df_results = pd.DataFrame(results)

    # Resumen agrupado
    summary = df_results.groupby("fraction").agg({
        "n_samples_train": "first",
        "f1_val_eval": ["mean", "std"],
        "brier_score_val_eval": ["mean", "std"],
        "roc_auc_val_eval": ["mean", "std"],
        "train_seconds": "mean",
    }).reset_index()

    print("\n" + "=" * 75)
    print("[research.sensitivity_m0] RESULTADOS CORREGIDOS (FUERA DE MUESTRA D_val_eval N=13,629):")
    print("=" * 75)
    for _, r in summary.iterrows():
        frac_pct = f"{int(r['fraction'].values[0]*100)}%"
        n_tr = int(r["n_samples_train"].values[0])
        f1_m, f1_s = r["f1_val_eval"]["mean"], r["f1_val_eval"]["std"]
        br_m, br_s = r["brier_score_val_eval"]["mean"], r["brier_score_val_eval"]["std"]
        auc_m = r["roc_auc_val_eval"]["mean"]
        t_sec = r["train_seconds"]["mean"]
        print(f"  + Nivel {frac_pct:>4} (N={n_tr:,}): F1 = {f1_m:.4f} (±{f1_s:.4f}) | Brier = {br_m:.4f} (±{br_s:.4f}) | AUC = {auc_m:.4f} | Tiempo = {t_sec:.2f}s")

    exp_dir = get_experiments_dir()
    exp_dir.mkdir(parents=True, exist_ok=True)
    out_csv = exp_dir / "SENSIBILIDAD_M0_CORREGIDA.csv"
    df_results.to_csv(out_csv, index=False)
    # Mantener alias de compatibilidad
    df_results.to_csv(exp_dir / "SENSIBILIDAD_ENTRENAMIENTO_M0.csv", index=False)

    # Guardar métricas de calibración
    calib_summary = []
    for frac in fractions:
        sub = df_results[df_results["fraction"] == frac]
        calib_summary.append({
            "model": f"M0_Lexico_{int(frac*100)}pct",
            "n_train": int(sub["n_samples_train"].iloc[0]),
            "n_cal": int(sub["n_samples_cal"].iloc[0]),
            "n_eval": int(sub["n_samples_val_eval"].iloc[0]),
            "mean_brier_score": float(sub["brier_score_val_eval"].mean()),
            "std_brier_score": float(sub["brier_score_val_eval"].std()),
            "mean_log_loss": float(sub["log_loss_val_eval"].mean()),
            "mean_roc_auc": float(sub["roc_auc_val_eval"].mean()),
            "mean_f1": float(sub["f1_val_eval"].mean()),
        })
    pd.DataFrame(calib_summary).to_csv(exp_dir / "CALIBRACION_M0.csv", index=False)

    # Congelar artefacto M0 definitivo
    if best_model is not None:
        model_out = Path("artifacts/models_reproduced/m0_reproduced.joblib")
        model_out.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(best_model, model_out)
        
        mod_m0_dir = Path("MODELOS/M0")
        mod_m0_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(best_model, mod_m0_dir / "model.joblib")
        print(f"\n  + Modelo M0 definitivo congelado guardado en {mod_m0_dir / 'model.joblib'}")

    print("=" * 75)
    return df_results

if __name__ == "__main__":
    run_m0_sensitivity()
