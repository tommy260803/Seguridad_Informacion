#!/usr/bin/env python
"""Final verification of all bug fixes."""
import sys
import re
sys.path.insert(0, '.')

print("=" * 60)
print("FINAL BUG FIX VERIFICATION")
print("=" * 60)

results = []

# BUG-01: Timeout conflict
print("\n[BUG-01] Timeout conflict between client (6000ms) and backend (8000ms)")
with open('extension/background.js', 'r') as f:
    bg = f.read()
timeoutms = re.search(r'const timeoutMs = (\d+);', bg)
main_uses_timeoutMs = 'AbortSignal.timeout(timeoutMs)' in bg
bug01 = timeoutms and int(timeoutms.group(1)) == 8000 and main_uses_timeoutMs
results.append(bug01)
print(f"  Client timeout set to 8000ms: {'PASS' if bug01 else 'FAIL'}")
print(f"  Main check uses timeoutMs variable: {'PASS' if main_uses_timeoutMs else 'FAIL'}")

# BUG-02: Synchronous DNS resolution
print("\n[BUG-02] Synchronous DNS blocking event loop")
with open('src/phishguard_infra/policy.py', 'r') as f:
    pol = f.read()
bug02 = 'import asyncio' in pol and 'asyncio.to_thread' in pol
results.append(bug02)
print(f"  import asyncio present: {'PASS' if 'import asyncio' in pol else 'FAIL'}")
print(f"  asyncio.to_thread for DNS: {'PASS' if 'asyncio.to_thread' in pol else 'FAIL'}")

# BUG-03: Homoglyph/IDN discrepancy
print("\n[BUG-03] Homoglyph detection with IDN/Punycode")
from src.phishguard_ml.homoglyphs import analyze_homoglyphs
result = analyze_homoglyphs('www.xn--pple-43d.com', 'apple.com')
bug03 = result['is_spoofing'] == True
results.append(bug03)
print(f"  xn--pple-43d with apple.com -> is_spoofing={result['is_spoofing']}: {'PASS' if bug03 else 'FAIL'}")

# BUG-04: Separate uncertainty/abstention thresholds
print("\n[BUG-04] Separate early-stopping and abstention thresholds")
from src.phishguard_orchestrator.models import AdaptivePolicy
pol = AdaptivePolicy()
bug04 = pol.uncertainty_threshold == 0.15 and pol.abstention_threshold == 0.20
results.append(bug04)
print(f"  uncertainty_threshold=0.15 (early stop): {'PASS' if pol.uncertainty_threshold == 0.15 else 'FAIL'}")
print(f"  abstention_threshold=0.20 (final): {'PASS' if pol.abstention_threshold == 0.20 else 'FAIL'}")

# BUG-05: force_visual overriding M3 with empty data
print("\n[BUG-05] M3 receiving empty infrastructure/DOM variables")
with open('src/phishguard_api/worker.py', 'r') as f:
    wk = f.read()
# Check that force_visual is not in the main code path
force_visual_in_code = 'if force_visual and' in wk.split('while True:')[0] if 'while True:' in wk else False
bug05 = not force_visual_in_code
results.append(bug05)
print(f"  force_visual override removed from code path: {'PASS' if bug05 else 'FAIL'}")

# BUG-06: LLM overwriting M2 probability
print("\n[BUG-06] LLM unconditionally overriding M2 probability")
bug06 = '0.7 * probability + 0.3 * float(llm_prob)' in wk
results.append(bug06)
print(f"  LLM weighted combination present: {'PASS' if bug06 else 'FAIL'}")

# BUG-07: www. prefix treatment
print("\n[BUG-07] www. prefix normalization in feature extraction")
from src.phishguard_ml.features import _strip_www
bug07 = _strip_www('www.google.com') == 'google.com' and _strip_www('google.com') == 'google.com'
results.append(bug07)
print(f"  strip_www('www.google.com') = 'google.com': {'PASS' if _strip_www('www.google.com') == 'google.com' else 'FAIL'}")
print(f"  strip_www('google.com') = 'google.com': {'PASS' if _strip_www('google.com') == 'google.com' else 'FAIL'}")

# Summary
print("\n" + "=" * 60)
print(f"SUMMARY: {sum(results)}/7 bugs fixed")
all_pass = all(results)
print(f"ALL BUGS FIXED: {all_pass}")
if not all_pass:
    print("Still needing attention:")
    for i, r in enumerate(results):
        if not r:
            print(f"  - Bug {i+1}")