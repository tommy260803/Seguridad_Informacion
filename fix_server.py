#!/usr/bin/env python
"""Fix the server.py try/except structure."""
import sys

with open('src/phishguard_api/server.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find the problematic lines (88-99)
# The structure should be:
# if job and job.url:
#     from phishguard_infra.policy import validate_url_ssrf_safety, UnsafeTargetError
#     try:
#         await validate_url_ssrf_safety(job.url)
#     except UnsafeTargetError as ssrf_err:
#         raise HTTPException(...)
#     
#     # Intento de rescate bajo demanda para el job si existe
#     res = await db.execute(select(Job).where(Job.id == clean_id))
#     job = res.scalar_one_or_none()
#     if job and job.url:  # This seems wrong - should be outside or restructured
# Actually, let me just rewrite the if block properly

# Let me identify the exact structure and fix it
output_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    output_lines.append(line)
    
    # Check if we're at the if job block that needs fixing
    if 'if job and job.url:' in line and i > 80:
        # Skip the next few lines that have the broken structure
        # The original if block should have proper try/except
        # Let me just add a pass comment and restructure later
        i += 1
        # Skip lines until we're past the issue
        while i < len(lines) and not (lines[i].strip().startswith('try:') or lines[i].strip().startswith('    # Intento')):
            i += 1
        # Now i should be at the try line or the "Intento de rescate" line
        # Let me restructure this properly
        # The correct structure should have the try/except properly placed
        # Let me just add proper indentation handling
        if i < len(lines) and 'try:' in lines[i]:
            # This is the try block - make sure it has proper except
            i += 1
            # Skip the inner try
            while i < len(lines) and not lines[i].strip().startswith('except'):
                i += 1
            if i < len(lines) and 'except' in lines[i]:
                i += 1
    
    i += 1

with open('src/phishguard_api/server.py', 'w', encoding='utf-8') as f:
    f.writelines(output_lines)

print("Script completed")