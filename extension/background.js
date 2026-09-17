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

  const { endpoint, allowed_urls } = await chrome.storage.local.get({ endpoint: DEFAULT_ENDPOINT, allowed_urls: [] });

  if (allowed_urls && allowed_urls.includes(url)) {
    return;
  }

  try {
    const startRes = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    
    if (startRes.ok) {
      const job = await startRes.json();
      const finalResult = await pollAnalysis(endpoint, job.id);
      
      if (finalResult.decision === "phishing") {
        const warningUrl = chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}&jobId=${job.id}`);
        chrome.tabs.update(details.tabId, { url: warningUrl });
      }
    }
  } catch (error) {
    console.error("Error validando URL en background:", error);
  }
});
