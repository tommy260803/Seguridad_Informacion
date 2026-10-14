"""Barrido de secretos/credenciales/PII sobre TODO el árbol rastreado (pre-commit).

Modo árbol completo (condición C-4 de la auditoría técnica final):
  - Escanea `git ls-files` (todo lo rastreado) + archivos no rastreados no ignorados.
  - Ignora binarios por extensión/tamaño, no solo los modificados.
  - Clasifica hallazgos en:
      * SECRET real (patrón de clave/token)  -> exit=1
      * PREEXISTENTE documentado (p. ej. extension.pem, clave de firma de la
        extensión rastreada desde antes de esta fase; ver LIMITACIONES_RESTANTES.md)
        -> reportado, no bloquea, pero DEBE figurar en el informe.
  - Ejecutar SIEMPRE antes de `git add`/`git commit`.

Salida: lista hallazgos + resumen; exit code 1 solo si hay SECRET no documentado.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Artefactos de credenciales PREEXISTENTES conocidos y documentados en esta fase.
# No son secretos introducidos por esta fase: se rastrean desde el commit base.
# Su riesgo y la recomendación de rotación están en LIMITACIONES_RESTANTES.md.
PREEXISTING_DOCUMENTED = {
    "extension.pem": (
        "clave de firma de la extensión Chrome, rastreada desde antes de esta fase "
        "(ver LIMITACIONES_RESTANTES.md: recomendación de rotación/exclusión)"
    ),
}

SKIP_SUFFIXES = (
    ".zip", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".docx", ".xlsx", ".bin",
    ".pyc", ".joblib", ".pem.bak", ".ico", ".woff", ".woff2", ".ttf", ".eot",
)
MAX_BYTES = 3_000_000

PATS = {
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "gh_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    "sk_token": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "bearer": re.compile(r"bearer\s+[A-Za-z0-9._\-]{20,}", re.I),
    "priv_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "passwd_eq": re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{6,}", re.I),
    "api_key_assign": re.compile(
        r"(?:api[_-]?key|token|secret)\s*[=:]\s*[\"'][A-Za-z0-9\-_.]{16,}", re.I
    ),
    "generic_pem_key": re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
}

# Ficheros de solo texto que contienen patrones "ruidosos" ya revisados a mano
# (URLs públicas de dataset, ejemplos documentados): no son secretos.
ALLOWLIST_BY_PATH: dict[str, tuple[str, ...]] = {
    # 01_AUDITORIA_BASELINE.md cita (como hallazgo documentado) la URL pública del
    # dataset wokwi/Firebase: el parámetro apiKey=AIza... es un identificador OAuth
    # público de Firebase dentro de una URL analizada, no una clave del proyecto.
    "01_AUDITORIA_BASELINE.md": ("google_api_key",),
}


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, encoding="utf-8", cwd=ROOT
    ).stdout
    paths = [ROOT / p.strip() for p in out.splitlines() if p.strip()]
    # añadir no rastreados no ignorados
    out2 = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        capture_output=True, text=True, encoding="utf-8", cwd=ROOT,
    ).stdout
    paths.extend(ROOT / p.strip() for p in out2.splitlines() if p.strip())
    # dedup preservando orden
    seen: set[str] = set()
    uniq: list[Path] = []
    for p in paths:
        key = str(p)
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq


def main() -> int:
    secrets: list[tuple[str, str, str]] = []
    preexisting: list[tuple[str, str, str]] = []
    n_scanned = 0
    n_missing = 0

    for pt in tracked_files():
        rel = str(pt.relative_to(ROOT)).replace("\\", "/")
        if not pt.is_file():
            n_missing += 1
            continue
        if pt.suffix.lower() in SKIP_SUFFIXES:
            continue
        if pt.stat().st_size > MAX_BYTES:
            continue
        try:
            txt = pt.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        n_scanned += 1
        for name, pat in PATS.items():
            m = pat.search(txt)
            if not m:
                continue
            hit = (rel, name, m.group(0)[:60])
            if rel in PREEXISTING_DOCUMENTED:
                preexisting.append(hit + (PREEXISTING_DOCUMENTED[rel],))  # type: ignore[arg-type]
            elif name in ALLOWLIST_BY_PATH.get(rel, ()):
                continue  # patrón ruidoso justificado en la propia lista
            else:
                secrets.append(hit)

    print(f"archivos escaneados: {n_scanned} (rastreados + no ignorados); no encontrados: {n_missing}")
    if preexisting:
        print("PREEXISTENTE DOCUMENTADO (no bloquea; ver LIMITACIONES_RESTANTES.md):")
        for rel, name, frag, note in preexisting:
            print(f"  [{name}] {rel} -> {frag!r} | {note}")
    if secrets:
        print("SECRETO NO DOCUMENTADO (bloquea commit):")
        for rel, name, frag in secrets:
            print(f"  [{name}] {rel} -> {frag!r}")
        return 1
    print("sin secretos no documentados")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
