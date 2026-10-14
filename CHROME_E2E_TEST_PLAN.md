# Chrome E2E Testing Plan (PhishPe Extension)

## Purpose
Plan de pruebas de extremo a extremo para la extensión PhishPe en instancias controladas de Google Chrome conectadas con el backend mediante HTTP real.

## Tools Required
- Google Chrome browser (controlled instance)
- Playwright or Selenium for automation
- Backend running via `http://localhost:8080/check`

## Test Scenarios

### 1. Navigation and Detection
- Navigate to known phishing URLs (PhishTank verified)
- Navigate to known legitimate URLs (Tranco verified)
- Observe badge changes and warning pages

### 2. Advertisements Visibles
- Verify `!` badge for phishing
- Verify `?` badge for suspicious
- Verify `✔` badge for legitimate

### 3. Legitimate and Malicious Decisions
- M0-only mode (HybridM0Model via POST /check)
- Full cascade mode (M0→M1→M2→M3→M4/M5 via POST /analyses)
- Measure time from navigation to decision

### 4. Abstention
- URLs where cascade abstains
- Observe behavior when all modalities exhausted

### 5. DNS, TLS, and HTTP Errors
- Network offline mode
- DNS resolution failures
- TLS certificate errors
- HTTP error responses

### 6. Timeouts
- Backend timeout scenarios
- Sandbox task timeouts
- Observe fail-safe behavior

### 7. Redirects
- URL shorteners (bit.ly, tinyurl.com, etc.)
- HTTP 301/302 redirects
- Follow redirect before analysis

### 8. Homoglyphs and Punycode
- `xn--pple-43d.com` (apple homoglyph)
- `www.facebuuk.com` (Cyrillic homoglyph)
- Detect and show warning

### 9. Cold and Hot Cache
- First navigation (cold cache)
- Subsequent navigation (hot cache)
- Verify cache invalidation after 3min (180000ms)

### 10. Concurrency
- Multiple simultaneous navigations
- Verify no race conditions

### 11. Backend Failures
- Backend unreachable
- Backend returns errors
- Graceful degradation

### 12. Offline Behavior
- No internet connectivity
- Observe local feature extraction only

## Measurement Metrics
- Latency navigation to visible decision
- Total API latency
- Latency per modality
- P50, P90, P95, P99 per scenario
- Timeout rate
- Failure percentage
- Resource consumption (CPU, memory)
- Abstention rate by class

## Data to Collect Per Request
- URL analyzed
- Decision (phishing/legitimate/warning)
- Probability
- Modalities consulted
- Total latency
- Success/failure of each modality
- Cache state (hit/miss)
- Timestamp

## Isolation Requirements
- No real credentials
- No interaction with dangerous forms
- Isolated network environment
- Logs saved for audit

## Expected Results (based on internal evaluation)
- M0-only: F1=0.8658, FPR=3.20%
- Full cascade: F1=0.9248, FPR=0.40%
- With www normalization: FPR drops significantly
- Homoglyph detection: correct for xn-- and Cyrillic

## Script Structure (using Playwright)
```python
async def test_phishing_detection():
    page = await playwright.chromium.launch(headless=True).new_page()
    await page.goto("https://www.facebuuk.com/")
    # Wait for badge update
    # Read decision from extension message
    # Assert decision == "phishing"
```