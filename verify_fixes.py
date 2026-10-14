#!/usr/bin/env python
"""Verify all bug fixes are in place."""
import sys
sys.path.insert(0, '.')

from src.phishguard_ml.homoglyphs import analyze_homoglyphs

# BUG-03 FIX: Homoglyph/Punycode
result = analyze_homoglyphs('www.xn--pple-43d.com', 'apple.com')
bug03_pass = result['is_spoofing'] == True
print(f"BUG-03 FIX: xn--pple-43d with apple.com -> is_spoofing={result['is_spoofing']} (expected True): {'PASS' if bug03_pass else 'FAIL'}")

# BUG-07 FIX: www. normalization
from src.phishguard_ml.features import _strip_www
test_cases = [
    ('www.google.com', 'google.com'),
    ('google.com', 'google.com'),
]
www_pass = all(_strip_www(h) == r for h, r in test_cases)
print(f"BUG-07 FIX: strip_www() normalization: {'PASS' if www_pass else 'FAIL'}")

# BUG-02 FIX: policy.py has asyncio import and to_thread usage
with open('src/phishguard_infra/policy.py', 'r') as f:
    policy_source = f.read()
bug02_pass = 'asyncio.to_thread' in policy_source and 'import asyncio' in policy_source
print(f"BUG-02 FIX: policy.py has asyncio.import and asyncio.to_thread: {'PASS' if bug02_pass else 'FAIL'}")

# BUG-01 FIX: background.js timeout
with open('extension/background.js', 'r') as f:
    bg_source = f.read()
has_8000 = '8000' in bg_source.split('AbortSignal.timeout')[1].split(')')[0] if 'AbortSignal.timeout' in bg_source else False
bug01_pass = has_8000
print(f"BUG-01 FIX: background.js timeout 8000ms: {'PASS' if bug01_pass else 'FAIL'}")

# BUG-04 FIX: cascade thresholds
from src.phishguard_orchestrator.models import AdaptivePolicy
policy = AdaptivePolicy()
bug04_pass = policy.uncertainty_threshold == 0.15 and policy.abstention_threshold == 0.20
print(f"BUG-04 FIX: uncertainty_threshold=0.15, abstention_threshold=0.20: {'PASS' if bug04_pass else 'FAIL'}")

# BUG-05 FIX: force_visual removed
from src.phishguard_api import worker
import inspect
try:
    source_w = inspect.getsource(worker.process_job)
    bug05_pass = 'force_visual' not in source_w
except:
    # If we can't get the source, check the file directly
    with open('src/phishguard_api/worker.py', 'r') as f:
        w_source = f.read()
    bug05_pass = 'force_visual' not in w_source
print(f"BUG-05 FIX: force_visual override removed: {'PASS' if bug05_pass else 'FAIL'}")

# BUG-06 FIX: LLM weighted combination
bug06_pass = '0.7 * probability + 0.3 * float(llm_prob)' in source_w if 'source_w' in dir() else '0.7 * probability + 0.3 * float(llm_prob)' in w_source
print(f"BUG-06 FIX: LLM weighted combination: {'PASS' if bug06_pass else 'FAIL'}")

print(f"\n{'='*50}")
print(f"BUG FIX SUMMARY:")
print(f"  BUG-01 (timeout): {'FIXED' if bug01_pass else 'NOT FIXED'}")
print(f"  BUG-02 (async DNS): {'FIXED' if bug02_pass else 'NOT FIXED'}")
print(f"  BUG-03 (homoglyph): {'FIXED' if bug03_pass else 'NOT FIXED'}")
print(f"  BUG-04 (thresholds): {'FIXED' if bug04_pass else 'NOT FIXED'}")
print(f"  BUG-05 (force_visual): {'FIXED' if bug05_pass else 'NOT FIXED'}")
print(f"  BUG-06 (LLM override): {'FIXED' if bug06_pass else 'NOT FIXED'}")
print(f"  BUG-07 (www. normalization): {'FIXED' if www_pass else 'NOT FIXED'}")
print(f"\nTotal: {sum([bug01_pass, bug02_pass, bug03_pass, bug04_pass, bug05_pass, bug06_pass, www_pass])}/7 fixed")