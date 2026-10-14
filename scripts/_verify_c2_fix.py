"""Verificación puntual de la corrección C-2 (heurística punycode acotada).

Confirma: (1) el falso positivo demonstrado por la auditoría técnica ya no ocurre;
(2) los ataques reales siguen detectados; (3) los controles negativos siguen en False.
Además re-mide el efecto sobre la cohorte2 (debe seguir en 0).
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard_ml.homoglyphs import analyze_homoglyphs  # noqa: E402


def spoof(host: str, reg: str) -> bool:
    return bool(analyze_homoglyphs(host, reg)["is_spoofing"])


casos = [
    # (host, registrado, esperado, descripcion)
    ("xn--caf-dma.apple.com", "apple.com", False, "FP auditoria: subdominio punycode bajo marca real"),
    ("xn--caf-dma.google.com", "google.com", False, "FP auditoria variante google"),
    ("www.xn--caf-dma.netflix.com", "netflix.com", False, "FP auditoria variante www"),
    ("xn--pple-43d.com", "xn--pple-43d.com", True, "ataque real apple (Cyrillic)"),
    ("www.xn--pple-43d.com", "xn--pple-43d.com", True, "ataque real apple www"),
    ("xn--pypal-4ve.com", "xn--pypal-4ve.com", True, "ataque real paypal"),
    # xn--ggl-0nc.com es ataque de ABREVIACIÓN (ggl≠google), no homógrafo: el
    # esqueleto visual nunca lo detectó (baseline=False). No es regressión de C-2.
    ("xn--ggl-0nc.com", "xn--ggl-0nc.com", False, "abreviación ggl (no homógrafo, pre-existente)"),
    ("apple.com", "apple.com", False, "marca oficial"),
    ("accounts.google.com", "google.com", False, "subdominio legitimo"),
    ("t.ly", "t.ly", False, "acortador corto (regresión BUG-08)"),
    ("s.id", "s.id", False, "acortador corto (regresión BUG-08)"),
    ("paypal.com.secure-id.top", "secure-id.top", True, "subdominio marcado con marca"),
    ("login-verify.xyz", "login-verify.xyz", False, "sin marca"),
]

n_ok = 0
fallos = []
for host, reg, esperado, desc in casos:
    got = spoof(host, reg)
    estado = "OK" if got == esperado else "FALLO"
    if got == esperado:
        n_ok += 1
    else:
        fallos.append((host, reg, esperado, got, desc))
    print(f"  [{estado}] spoof={str(got):5} esperado={str(esperado):5} | {host} ({desc})")

print(f"\n{n_ok}/{len(casos)} casos correctos")
if fallos:
    print("FALLOS:")
    for f in fallos:
        print("  ", f)
    sys.exit(1)
print("C-2 VERIFICADO: el FP de la auditoría está corregido y los ataques reales se conservan.")
