/**
 * PhishGuard Pro - Background Service Worker
 * Real-time non-intrusive URL inspection, Tranco prevalence shield, and badge management.
 */

const CHECK_ENDPOINT = "http://localhost:8080/check";
const analysisCache = new Map();

// Helper to update extension badge
function updateTabBadge(tabId, decision, probability) {
  if (!tabId || tabId < 0) return;
  try {
    if (decision === "phishing") {
      chrome.action.setBadgeText({ tabId, text: "!" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
      chrome.action.setTitle({ tabId, title: `PhishGuard: ¡Amenaza de Phishing Detectada! (${Math.round(probability * 100)}%)` });
    } else if (decision === "warning") {
      chrome.action.setBadgeText({ tabId, text: "?" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#f59e0b" });
      chrome.action.setTitle({ tabId, title: `PhishGuard: Sospechoso / Precaución (${Math.round(probability * 100)}%)` });
    } else {
      chrome.action.setBadgeText({ tabId, text: "✔" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#10b981" });
      chrome.action.setTitle({ tabId, title: `PhishGuard: Dominio Auténtico Verificado (${Math.round(probability * 100)}%)` });
    }
  } catch (_) {}
}

async function checkUrl(url, endpoint, userCountry) {
  console.log("[PhishGuard Background] Analizando:", url);
  const timeoutMs = 8000; // Tiempo coherente con el límite del backend (WHOIS/GeoIP)
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, user_country: userCountry || undefined }),
    signal: AbortSignal.timeout(timeoutMs)
  });

  if (!response.ok) {
    // Si la petición fue abortada por timeout, informamos en lugar de fallar en silencio
    if (response.type === "error" && response.reason instanceof DOMException) {
      console.warn("[PhishGuard] Timeout excedendido en consulta de análisis:", url);
      throw new Error(`Timeout de análisis URL (${timeoutMs}ms): el backend no respondió a tiempo. Se recomienda incrementar el presupuesto de tiempo o verificar conectividad del backend.`);
    }
    throw new Error(`HTTP Error: ${response.status}`);
  }
  const data = await response.json();
  console.log("[PhishGuard Background] Resultado:", data);
  return data;
}

// Listener for messages from popup or warning page
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "analyze") return;

  chrome.storage.local.get({ endpoint: CHECK_ENDPOINT, user_country: "" }).then(async ({ endpoint, user_country }) => {
    let targetEndpoint = endpoint;
    if (targetEndpoint && targetEndpoint.includes("/analyses")) {
      targetEndpoint = CHECK_ENDPOINT;
      chrome.storage.local.set({ endpoint: CHECK_ENDPOINT });
    }

    try {
      const result = await checkUrl(message.url, targetEndpoint, user_country);
      analysisCache.set(message.url, result);
      if (sender?.tab?.id) {
        updateTabBadge(sender.tab.id, result.decision, result.probability);
      }
      sendResponse({ success: true, data: result });
    } catch (err) {
      sendResponse({ success: false, error: err.message });
    }
  });

  return true; // Keep sendResponse async channel open
});

// Non-intrusive navigation listener:
// Never interrupts authentic domains. Only intercepts confirmed phishing attacks.
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;

  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) return;
  if (url.startsWith("http://localhost") || url.startsWith("http://127.0.0.1")) return;

  let origin = "";
  try {
    origin = new URL(url).origin;
  } catch (_) { return; }

  // Check user exceptions
  const { endpoint, allowed_urls, user_country } = await chrome.storage.local.get({
    endpoint: CHECK_ENDPOINT,
    allowed_urls: [],
    user_country: ""
  });

  const ALLOW_EXPIRY_MS = 24 * 60 * 60 * 1000;
  const isAllowed = (allowed_urls || []).some(entry => {
    if (typeof entry === "string") return entry === origin;
    if (entry && entry.origin === origin) {
      return (Date.now() - entry.timestamp) < ALLOW_EXPIRY_MS;
    }
    return false;
  });

  if (isAllowed) {
    console.log("[PhishGuard] Origen en lista de excepciones del usuario:", origin);
    return;
  }

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

  let targetEndpoint = endpoint && !endpoint.includes("/analyses") ? endpoint : CHECK_ENDPOINT;

  // Background check
  try {
    let result = analysisCache.get(url);
    if (!result || (Date.now() - (result._ts || 0) > 180000)) {
      result = await checkUrl(url, targetEndpoint, effectiveCountry);
      result._ts = Date.now();
      analysisCache.set(url, result);
    }

    updateTabBadge(details.tabId, result.decision, result.probability);

    // Don't intercept warning page itself
    if (url.includes("warning.html")) return;

    // Interception criteria:
    // A) High confidence phishing attack
    const isPhishing = result.decision === "phishing" && (result.probability >= 0.50 || result.homoglyphs?.is_spoofing);

    // B) Regional bank/entity collision (e.g. bcp.com in China/Japan vs viabcp.com in Peru)
    const hasLocalSuggestions = Boolean(result.local_suggestions && result.local_suggestions.length > 0 && result.geo_context?.is_foreign);
    const hasBrandMismatch = Boolean(result.brand_mismatch);
    const isRegionalWarning = (result.decision === "warning" || hasLocalSuggestions || hasBrandMismatch) && (hasLocalSuggestions || hasBrandMismatch);

    if (isPhishing || isRegionalWarning) {
      console.warn("[PhishGuard] Interceptando navegación para advertencia:", url, { isPhishing, isRegionalWarning });

      const topSuggestion = (result.local_suggestions && result.local_suggestions.length > 0) ? result.local_suggestions[0] : null;
      const targetBrand = result.brand_analysis?.closest_brand || result.homoglyphs?.target_brand || (topSuggestion ? topSuggestion.brand_name : "");

      const params = new URLSearchParams({
        url: url,
        jobId: result.job_id || "",
        probability: String(result.probability),
        decision: isPhishing ? "phishing" : "warning",
        target_brand: targetBrand
      });

      if (topSuggestion) {
        params.set("bm_name", topSuggestion.brand_name || "");
        params.set("bm_domain", topSuggestion.suggested_domain || "");
        params.set("bm_category", topSuggestion.category || "bank");
        params.set("bm_suggestion", topSuggestion.reason || "");
        params.set("bm_diff", "1");
      } else if (result.brand_mismatch) {
        const bm = result.brand_mismatch;
        params.set("bm_name", bm.brand_full_name || "");
        params.set("bm_domain", bm.local_domain || "");
        params.set("bm_category", bm.category || "bank");
        params.set("bm_suggestion", bm.suggestion || "");
      }

      // Save rules and mismatch data to local storage for warning.js
      const bmPayload = result.brand_mismatch || (topSuggestion ? {
        brand_full_name: topSuggestion.brand_name,
        local_domain: topSuggestion.suggested_domain,
        current_domain: origin ? new URL(url).hostname : url,
        category: topSuggestion.category,
        is_different_entity: true,
        suggestion: topSuggestion.reason
      } : null);

      await chrome.storage.local.set({
        [`rules_${url}`]: result.rules_analysis,
        [`brand_mismatch_${url}`]: bmPayload
      });

      const warningUrl = chrome.runtime.getURL(`warning.html?${params.toString()}`);
      chrome.tabs.update(details.tabId, { url: warningUrl });
    }
  } catch (err) {
    console.warn("[PhishGuard] Fallo pasivo de verificación en background:", err);
  }
});
