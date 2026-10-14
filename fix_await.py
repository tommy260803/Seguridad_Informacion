#!/usr/bin/env python
"""Fix await calls in server.py"""
with open('src/phishguard_api/server.py', 'r', encoding='utf-8') as f:
    content = f.read()

fixes = [
    # Fix 1: position 3280
    ("            validate_url_ssrf_safety(job.url)\n        except UnsafeTargetError",
     "            await validate_url_ssrf_safety(job.url)\n        except UnsafeTargetError"),
    # Fix 2: position 5015
    ("                validate_url_ssrf_safety(job.url)\n            except UnsafeTargetError",
     "                await validate_url_ssrf_safety(job.url)\n            except UnsafeTargetError"),
    # Fix 3: positions 7600/7661 (combined pattern)
    ("        validate_url_ssrf_safety(url)\n    except UnsafeTargetE",
     "        await validate_url_ssrf_safety(url)\n    except UnsafeTargetE"),
    # Fix 4: position 11631
    ("        validate_url_ssrf_safety(url)\n    except UnsafeTargetE",
     "        await validate_url_ssrf_safety(url)\n    except UnsafeTargetE"),
]

for old, new in fixes:
    count = content.count(old)
    if count > 0:
        content = content.replace(old, new)
        print(f"Fixed {count} occurrence(s) of pattern")
    else:
        print(f"Pattern not found, checking context...")

with open('src/phishguard_api/server.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Done fixing server.py")