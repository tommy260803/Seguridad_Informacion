"""Package the complete, audited, and reproducible Scopus evidence archive.

Creates `evidencia_phishpe_corregida_scopus.zip` in the project root containing:
1. Documentation & Traceability Guides (`INFORME_AUDITORIA_Y_TRAZABILIDAD_SCOPUS.md`, etc.)
2. Dependency locks (`pyproject.toml`, `requirements-lock.txt`)
3. Processed dataset & splits (`data/processed/0.1.0/`)
4. Raw modality JSONLs & separated authentic/synthetic visual JSONLs (`artifacts/analysis-results/`)
5. Preserved original snapshot (`artifacts/original_audit_snapshot/`)
6. Corrected audit results & authentic M3 model (`artifacts/corrected_audit/`)
7. All trained models (`.joblib`), predictions, metrics, figures, and screenshots
8. Source code (`src/`, `scripts/`, `configs/`, `extension/`, `tests/`) excluding `.env` and caches.
"""

from __future__ import annotations

from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ZIP_PATH = ROOT / "evidencia_phishpe_corregida_scopus.zip"

EXCLUDED_DIRS = {"__pycache__", ".pytest_cache", ".git", ".venv", "venv", "node_modules"}
EXCLUDED_EXTS = {".pyc", ".pyo"}
EXCLUDED_NAMES = {".env", ".env.local", ".env.production"}


def should_include(path: Path) -> bool:
    for part in path.parts:
        if part in EXCLUDED_DIRS:
            return False
    if path.name in EXCLUDED_NAMES or path.suffix in EXCLUDED_EXTS:
        return False
    return True


def add_path_to_zip(zf: zipfile.ZipFile, target: Path, added_files: set[str]) -> None:
    if not target.exists():
        print(f"WARNING: Missing path {target}")
        return
    if target.is_file():
        if should_include(target):
            rel = target.relative_to(ROOT).as_posix()
            if rel not in added_files:
                zf.write(target, rel)
                added_files.add(rel)
    elif target.is_dir():
        for file_path in sorted(target.rglob("*")):
            if file_path.is_file() and should_include(file_path):
                rel = file_path.relative_to(ROOT).as_posix()
                if rel not in added_files:
                    zf.write(file_path, rel)
                    added_files.add(rel)


def main() -> None:
    targets = [
        ROOT / "INFORME_AUDITORIA_Y_TRAZABILIDAD_SCOPUS.md",
        ROOT / "GUIA_REDACCION_Y_AUDITORIA_ARTICULO_APA7.md",
        ROOT / "INDEX_EVIDENCIA.md",
        ROOT / "pyproject.toml",
        ROOT / "requirements-lock.txt",
        ROOT / "data" / "processed" / "0.1.0",
        ROOT / "artifacts" / "analysis-results",
        ROOT / "artifacts" / "original_audit_snapshot",
        ROOT / "artifacts" / "corrected_audit",
        ROOT / "artifacts" / "evaluation",
        ROOT / "artifacts" / "figures",
        ROOT / "artifacts" / "url-baseline-0.2.0",
        ROOT / "artifacts" / "m0-temporal",
        ROOT / "artifacts" / "m0-temporal-host-unseen",
        ROOT / "artifacts" / "m0-real",
        ROOT / "artifacts" / "m1-real",
        ROOT / "artifacts" / "m2-real",
        ROOT / "artifacts" / "m3-real",
        ROOT / "artifacts" / "m4-real",
        ROOT / "artifacts" / "m5-real",
        ROOT / "artifacts" / "m0-ite-real",
        ROOT / "artifacts" / "m1-ite-real",
        ROOT / "artifacts" / "m2-ite-real",
        ROOT / "artifacts" / "m3-ite-real",
        ROOT / "artifacts" / "m0-v2",
        ROOT / "artifacts" / "m4-fixed-real",
        ROOT / "artifacts" / "visual-samples",
        ROOT / "artifacts" / "screenshots",
        ROOT / "artifacts" / "authentic-cdp-screenshots",
        ROOT / "artifacts" / "previews",
        ROOT / "src",
        ROOT / "scripts",
        ROOT / "configs",
        ROOT / "extension",
        ROOT / "tests",
    ]

    added_files: set[str] = set()
    with zipfile.ZipFile(ZIP_PATH, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for t in targets:
            add_path_to_zip(zf, t, added_files)

    size_mb = ZIP_PATH.stat().st_size / (1024 * 1024)
    print(f"Created {ZIP_PATH} ({size_mb:.2f} MB) with {len(added_files)} files.")

    # Verify critical audit items are inside the zip
    critical_checks = [
        "INFORME_AUDITORIA_Y_TRAZABILIDAD_SCOPUS.md",
        "requirements-lock.txt",
        "pyproject.toml",
        "data/processed/0.1.0/samples.csv",
        "data/processed/0.1.0/splits/temporal.csv",
        "artifacts/analysis-results/infrastructure-results-real.jsonl",
        "artifacts/analysis-results/content-results-real.jsonl",
        "artifacts/analysis-results/visual-results-real.jsonl",
        "artifacts/analysis-results/visual-results-authentic-cdp.jsonl",
        "artifacts/analysis-results/visual-results-synthetic-dom-proxy.jsonl",
        "artifacts/corrected_audit/statistical_comparisons_all.json",
        "artifacts/corrected_audit/robustness_evaluation_real.json",
        "artifacts/corrected_audit/m3_visual_audit_and_authentic_evaluation.json",
        "artifacts/corrected_audit/m3-authentic-cdp/model.joblib",
        "artifacts/corrected_audit/latency_benchmark_real.json",
        "artifacts/corrected_audit/llm_evaluation_summary.json",
        "artifacts/corrected_audit/llm_live_m5_abstained_results.json",
        "artifacts/corrected_audit/extension_architecture_and_hybrid_evaluation.json",
        "artifacts/corrected_audit/evaluation_summary_real.json",
        "artifacts/m0-temporal/predictions.csv",
        "artifacts/m0-temporal-host-unseen/predictions.csv",
    ]
    missing = [c for c in critical_checks if c not in added_files]
    if missing:
        raise RuntimeError(f"Missing critical files in ZIP: {missing}")
    print("All critical files verified inside ZIP!")


if __name__ == "__main__":
    main()
