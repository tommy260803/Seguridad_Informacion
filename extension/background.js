const DEFAULT_ENDPOINT = "http://localhost:8080/analyses";

// Helper para hacer polling
async function pollAnalysis(endpoint, jobId) {
  while (true) {
    const response = await fetch(`${endpoint}/${jobId}`);
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    const data = await response.json();
    if (data.status === "completed" || data.status === "failed") {
      return data;
    }
    await new Promise(resolve => setTimeout(resolve, 1000)); // Esperar 1 segundo
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "analyze") return;
  chrome.storage.local.get({ endpoint: DEFAULT_ENDPOINT }).then(async ({ endpoint }) => {
    try {
      // 1. Iniciar análisis
      const startRes = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: message.url })
      });
      if (!startRes.ok) throw new Error(`backend_http_${startRes.status}`);
      const job = await startRes.json();
      
      // 2. Hacer polling hasta terminar
      const finalResult = await pollAnalysis(endpoint, job.id);
      sendResponse({ ok: true, result: finalResult });
    } catch (error) {
      sendResponse({ ok: false, error: String(error.message || error) });
    }
  });
  return true;
});

// Autochequeo al navegar
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Solo procesar la ventana principal
  const url = details.url;
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;

  // 1. FAST-PASS: Lista blanca global de sitios masivos (Cero segundos de espera)
  const GLOBAL_SAFE_DOMAINS = [
    "youtube.com", "google.com", "facebook.com", "github.com", 
    "whatsapp.com", "netflix.com", "instagram.com", "twitter.com",
    "x.com", "linkedin.com", "viabcp.com", "bbva.pe", "tiktok.com"
  ];
  try {
    const urlObj = new URL(url);
    if (GLOBAL_SAFE_DOMAINS.some(domain => urlObj.hostname.endsWith(domain))) {
      return; // Dejar pasar instantáneamente
    }
  } catch(e) {}

  const { endpoint, allowed_urls, safe_url_redirecting } = await chrome.storage.local.get({ endpoint: DEFAULT_ENDPOINT, allowed_urls: [], safe_url_redirecting: {} });

  // 2. FAST-PASS LOCAL: Sitios que la IA ya aprobó o el usuario permitió
  if (allowed_urls && allowed_urls.some(allowed => url.startsWith(allowed))) {
    return;
  }

  // Prevenir bucle infinito si acabamos de validar que es seguro
  const now = Date.now();
  if (safe_url_redirecting && safe_url_redirecting[url]) {
     if (now - safe_url_redirecting[url] < 5000) { // válido por 5 segundos
        return; 
     }
  }

  try {
    const startRes = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    
    if (startRes.ok) {
      const job = await startRes.json();
      // INTERCEPTAR INSTANTANEAMENTE A LA SALA DE ESPERA
      const analyzingUrl = chrome.runtime.getURL(`analyzing.html?url=${encodeURIComponent(url)}&jobId=${job.id}`);
      chrome.tabs.update(details.tabId, { url: analyzingUrl });
    }
  } catch (error) {
    console.error("Error validando URL en background:", error);
  }
});
