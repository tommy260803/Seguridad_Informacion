const CHECK_ENDPOINT = "http://localhost:8080/check";

const GLOBAL_SAFE_DOMAINS = [
  "youtube.com", "google.com", "facebook.com", "github.com",
  "whatsapp.com", "netflix.com", "instagram.com", "twitter.com",
  "x.com", "linkedin.com", "viabcp.com", "bbva.pe", "tiktok.com"
];

const analysisCache = new Map();

async function checkUrl(url, endpoint, userCountry) {
  console.log("[PhishGuard] Checking URL:", url);
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, user_country: userCountry || undefined })
  });
  if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
  const data = await response.json();
  console.log("[PhishGuard] Result:", data);
  return data;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "analyze") return;
  chrome.storage.local.get({ endpoint: CHECK_ENDPOINT, user_country: "" }).then(async ({ endpoint, user_country }) => {
    let effectiveCountry = user_country;
    if (!effectiveCountry) {
      try {
        const geoResp = await fetch('https://ipwho.is/', { signal: AbortSignal.timeout(3000) });
        if (geoResp.ok) {
          const geoData = await geoResp.json();
          effectiveCountry = (geoData.country_code || '').toUpperCase();
          if (effectiveCountry) chrome.storage.local.set({ user_country: effectiveCountry });
        }
      } catch (e) {}
    }
    try {
      const result = await checkUrl(message.url, endpoint, effectiveCountry);
      sendResponse({ ok: true, result });
    } catch (error) {
      sendResponse({ ok: false, error: String(error.message || error) });
    }
  });
  return true;
});

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  
  if (!url.startsWith('http://') && !url.startsWith('https://')) return;
  if (url.startsWith('http://localhost') || url.startsWith('http://127.0.0.1')) return;

  try {
    const urlObj = new URL(url);
    if (GLOBAL_SAFE_DOMAINS.some(domain => urlObj.hostname.endsWith(domain))) {
      console.log("[PhishGuard] Safe domain, skipping:", urlObj.hostname);
      return;
    }
  } catch(e) { return; }

  const { endpoint, allowed_urls, safe_url_redirecting, user_country } = await chrome.storage.local.get({ 
    endpoint: CHECK_ENDPOINT, 
    allowed_urls: [], 
    safe_url_redirecting: {},
    user_country: ""
  });

  // Auto-detect country from IP if not set by user
  let effectiveCountry = user_country;
  if (!effectiveCountry) {
    try {
      const geoResp = await fetch('https://ipwho.is/', { signal: AbortSignal.timeout(3000) });
      if (geoResp.ok) {
        const geoData = await geoResp.json();
        effectiveCountry = (geoData.country_code || '').toUpperCase();
        if (effectiveCountry) {
          chrome.storage.local.set({ user_country: effectiveCountry });
          console.log("[PhishGuard] Auto-detected country:", effectiveCountry);
        }
      }
    } catch (e) {
      console.warn("[PhishGuard] Auto-detect failed:", e.message);
    }
  }

  let origin = "";
  try {
    origin = new URL(url).origin;
  } catch (_) { return; }
  
  const now = Date.now();
  const ALLOW_EXPIRY_MS = 24 * 60 * 60 * 1000;
  if (allowed_urls && Array.isArray(allowed_urls)) {
    const isAllowed = allowed_urls.some(entry => {
      if (typeof entry === 'string') return entry === origin;
      if (entry && entry.origin === origin) {
        return (now - entry.timestamp) < ALLOW_EXPIRY_MS;
      }
      return false;
    });
    if (isAllowed) {
      console.log("[PhishGuard] Allowed URL, skipping:", origin);
      return;
    }
    const validEntries = allowed_urls.filter(entry => {
      if (typeof entry === 'string') return false;
      return entry && (now - entry.timestamp) < ALLOW_EXPIRY_MS;
    });
    if (validEntries.length !== allowed_urls.length) {
      chrome.storage.local.set({ allowed_urls: validEntries });
    }
  }

  if (safe_url_redirecting && safe_url_redirecting[url]) {
    if (now - safe_url_redirecting[url] < 5000) {
      console.log("[PhishGuard] Recently checked, skipping:", url);
      return;
    }
  }

  if (analysisCache.has(url)) {
    const cached = analysisCache.get(url);
    const age = Date.now() - (cached.timestamp || 0);
    if (age < 60000) return; // Skip if checked less than 60s ago
    analysisCache.delete(url);
  }

  analysisCache.set(url, { pending: true, timestamp: Date.now() });

  // Store pending state and redirect IMMEDIATELY
  const pendingUrl = chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}&pending=true`);
  chrome.tabs.update(details.tabId, { url: pendingUrl });

  // Check URL in background — no longer blocks the redirect
  try {
    console.log("[PhishGuard] Starting check for:", url);
    const result = await checkUrl(url, endpoint, effectiveCountry);
    
    analysisCache.set(url, result);
    
    const decision = result.decision || 'phishing';
    const rulesData = result.rules_analysis || null;
    const brandMismatch = result.brand_mismatch || null;

    // Store result so warning.js can pick it up via polling
    chrome.storage.local.set({ 
      [`rules_${url}`]: rulesData,
      [`brand_mismatch_${url}`]: brandMismatch,
      [`result_${url}`]: {
        probability: result.probability,
        decision: decision,
        ready: true
      }
    });

    if (decision === 'phishing') {
      console.log("[PhishGuard] PHISHING DETECTED");
    } else if (decision === 'warning') {
      console.log("[PhishGuard] WARNING: brand-country mismatch");
    } else {
      console.log("[PhishGuard] URL is legitimate, allowing:", url);
      // Add to allowed_urls to prevent re-check loop
      chrome.storage.local.get({ allowed_urls: [] }).then(({ allowed_urls }) => {
        const entry = { origin: new URL(url).origin, timestamp: Date.now() };
        const updated = [...(Array.isArray(allowed_urls) ? allowed_urls : []), entry];
        chrome.storage.local.set({ allowed_urls: updated }).then(() => {
          chrome.tabs.update(details.tabId, { url: url });
        });
      });
    }
  } catch (error) {
    console.error("[PhishGuard] Check error:", error);
    // Store error so warning.js shows something
    chrome.storage.local.set({
      [`result_${url}`]: { probability: 0.5, decision: 'phishing', ready: true }
    });
  }
});
