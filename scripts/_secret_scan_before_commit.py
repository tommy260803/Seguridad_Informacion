"""Barrido de secretos/credenciales/PII sobre los archivos con cambios de git (pre-commit)."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

out = subprocess.run(
    ["git", "status", "--porcelain"], capture_output=True, text=True, encoding="utf-8", cwd=ROOT
).stdout

files = []
for line in out.splitlines():
    if line.startswith("?? ") or line.startswith((" M", "M ", " D", "D ", "A ", "MM")):
        p = line[3:].strip().strip('"')
        files.append(p)

pats = {
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "gh_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    "sk_token": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "bearer": re.compile(r"bearer\s+[A-Za-z0-9._\-]{20,}", re.I),
    "priv_key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "passwd_eq": re.compile(r"(password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{6,}", re.I),
    "api_key_assign": re.compile(
        r"(api[_-]?key|token|secret)\s*[=:]\s*[\"'][A-Za-z0-9\-_.]{16,}", re.I
    ),
}

hits = []
n = 0
for f in files:
    pt = ROOT / f
    if not pt.is_file():
        continue
    if pt.suffix.lower() in (".zip", ".png", ".jpg", ".pdf", ".docx", ".bin", ".pyc"):
        continue
    if pt.stat().st_size > 3_000_000:
        continue
    try:
        txt = pt.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    n += 1
    for name, pat in pats.items():
        for m in pat.finditer(txt):
            hits.append((f, name, m.group(0)[:50]))

print("archivos escaneados:", n)
if hits:
    print("POSIBLES COINCIDENCIAS:")
    for h in hits:
        print("  ", h)
else:
    print("sin coincidencias de secretos/credenciales")
