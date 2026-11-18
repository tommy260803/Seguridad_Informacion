"""
Pruebas Automáticas de Validación y Calidad de Datos
Cohortes de Validación Externa - Revista Politécnica (Ecuador)
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PHASE1_DIR = ROOT / "paper_reproduction" / "01_external_validation"
COHORT2_PATH = ROOT / "artifacts" / "corrections_phase2" / "cohort2" / "cohort2_dataset.csv"
SAMPLES_PATH = ROOT / "data" / "processed" / "0.1.0" / "samples.csv"
MANIFEST_C_PATH = PHASE1_DIR / "external_cohort_manifest.csv"
RESULTS_PATH = PHASE1_DIR / "external_validation_results.csv"
SENSITIVITY_PATH = PHASE1_DIR / "source_sensitivity_analysis.csv"


@pytest.fixture(scope="session")
def train_identifiers():
    """Carga los dominios registrados y hashes SHA256 del conjunto de entrenamiento."""
    domains = set()
    url_shas = set()
    assert SAMPLES_PATH.exists(), f"No existe {SAMPLES_PATH}"
    with open(SAMPLES_PATH, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if r.get("registered_domain"):
                domains.add(r["registered_domain"].strip().lower())
            if r.get("canonical_url_sha256"):
                url_shas.add(r["canonical_url_sha256"].strip().lower())
    return {"domains": domains, "url_shas": url_shas}


@pytest.fixture(scope="session")
def cohort2_data():
    """Carga la cohorte histórica intacta."""
    assert COHORT2_PATH.exists(), f"No existe {COHORT2_PATH}"
    with open(COHORT2_PATH, encoding="utf-8") as f:
        return list(csv.DictReader(f))


@pytest.fixture(scope="session")
def cohort_c_manifest():
    """Carga el manifiesto de la nueva Cohorte C."""
    assert MANIFEST_C_PATH.exists(), f"No existe {MANIFEST_C_PATH}"
    with open(MANIFEST_C_PATH, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_cohort2_historical_integrity(cohort2_data):
    """Verifica que la cohorte histórica no haya sido alterada."""
    assert len(cohort2_data) == 1200, f"Cohorte 2 debe tener 1200 filas, tiene {len(cohort2_data)}"
    sources = [r["source"] for r in cohort2_data]
    from collections import Counter
    counts = Counter(sources)
    assert counts["urlhaus"] == 297
    assert counts["phishtank"] == 260
    assert counts["openphish"] == 43
    assert counts["tranco"] == 389
    assert counts["majestic"] == 211


def test_cohort_c_manifest_structure(cohort_c_manifest):
    """Verifica la estructura y unicidad de la Cohorte C."""
    assert len(cohort_c_manifest) == 1200, f"Cohorte C debe tener exactamente 1200 muestras, tiene {len(cohort_c_manifest)}"
    
    ids = [r["cohort_id"] for r in cohort_c_manifest]
    assert len(ids) == len(set(ids)), "Los IDs de cohorte deben ser estrictamente únicos"
    
    urls = [r["canonical_url"] for r in cohort_c_manifest]
    assert len(urls) == len(set(urls)), "Las URLs canónicas deben ser estrictamente únicas"
    
    shas = [r["canonical_url_sha256"] for r in cohort_c_manifest]
    assert len(shas) == len(set(shas)), "Los hashes SHA256 deben ser estrictamente únicos"


def test_cohort_c_class_balance(cohort_c_manifest):
    """Verifica que la Cohorte C esté perfectamente balanceada (50% phishing, 50% legítimo)."""
    labels = [r["validated_label"] for r in cohort_c_manifest]
    from collections import Counter
    counts = Counter(labels)
    assert counts["PHISHING_VERIFICADO"] == 600, f"Se esperaban 600 PHISHING_VERIFICADO, obtenidos {counts['PHISHING_VERIFICADO']}"
    assert counts["LEGITIMO_VERIFICADO"] == 600, f"Se esperaban 600 LEGITIMO_VERIFICADO, obtenidos {counts['LEGITIMO_VERIFICADO']}"


def test_no_train_domain_overlap(cohort_c_manifest, train_identifiers):
    """Verifica ausencia total de fuga de dominios contra el corpus de entrenamiento."""
    train_doms = train_identifiers["domains"]
    overlapping = []
    for r in cohort_c_manifest:
        reg = r.get("registered_domain", "").strip().lower()
        if reg and reg in train_doms:
            overlapping.append((r["cohort_id"], r["canonical_url"], reg))
    
    assert len(overlapping) == 0, f"Fuga de información detectada: {len(overlapping)} dominios solapados: {overlapping[:5]}"


def test_no_train_url_overlap(cohort_c_manifest, train_identifiers):
    """Verifica ausencia total de fuga de URLs contra el corpus de entrenamiento."""
    train_shas = train_identifiers["url_shas"]
    overlapping = []
    for r in cohort_c_manifest:
        sha = r.get("canonical_url_sha256", "").strip().lower()
        if sha and sha in train_shas:
            overlapping.append((r["cohort_id"], r["canonical_url"]))
    
    assert len(overlapping) == 0, f"Fuga de información detectada: {len(overlapping)} URLs solapadas: {overlapping[:5]}"


def test_label_taxonomy(cohort_c_manifest):
    """Verifica adhesión estricta a la taxonomía formal de 5 clases."""
    allowed = {
        "PHISHING_VERIFICADO",
        "LEGITIMO_VERIFICADO",
        "MALWARE_NO_PHISHING",
        "ETIQUETA_INCIERTA",
        "NO_VERIFICABLE",
    }
    for r in cohort_c_manifest:
        lbl = r.get("validated_label")
        assert lbl in allowed, f"Etiqueta desconocida o no permitida: {lbl} en muestra {r['cohort_id']}"


def test_structural_diversity_in_benign(cohort_c_manifest):
    """Verifica que las muestras legítimas incluyan URLs con rutas y no solo dominios bare."""
    legit_with_path = [
        r for r in cohort_c_manifest 
        if r["validated_label"] == "LEGITIMO_VERIFICADO" and int(r.get("has_path", 0)) == 1
    ]
    assert len(legit_with_path) >= 250, (
        f"Se esperaba diversidad estructural legítima con al menos 250 muestras con rutas, encontradas {len(legit_with_path)}"
    )


def test_no_urlhaus_in_phishing_class_c(cohort_c_manifest):
    """Verifica que el malware de URLhaus haya sido excluido completamente de la clase phishing en Cohorte C."""
    phish_urlhaus = [
        r for r in cohort_c_manifest 
        if r["source"] == "urlhaus"
    ]
    assert len(phish_urlhaus) == 0, "No debe existir ninguna muestra de URLhaus en Cohorte C"


def test_evaluation_results_mathematical_consistency():
    """Verifica consistencia matemática de las métricas reportadas en external_validation_results.csv."""
    assert RESULTS_PATH.exists(), f"No existe {RESULTS_PATH}"
    with open(RESULTS_PATH, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    
    for r in rows:
        n = int(r["n"])
        tp = int(r["tp"])
        tn = int(r["tn"])
        fp = int(r["fp"])
        fn = int(r["fn"])
        assert tp + tn + fp + fn == n, f"Matriz de confusión no suma n ({tp}+{tn}+{fp}+{fn} != {n}) en {r['cohort']} {r['model']}"
        
        acc = float(r["accuracy"])
        assert 0.0 <= acc <= 1.0
        
        prec = float(r["precision"])
        assert 0.0 <= prec <= 1.0
        
        rec = float(r["recall"])
        assert 0.0 <= rec <= 1.0
        
        f1 = float(r["f1"])
        assert 0.0 <= f1 <= 1.0
        
        fpr = float(r["fpr"])
        assert 0.0 <= fpr <= 1.0
