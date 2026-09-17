const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get("url");
const jobId = urlParams.get("jobId");

if (targetUrl) {
  document.getElementById("target-url").textContent = targetUrl;
}

const DEFAULT_ENDPOINT = "http://localhost:8080/analyses";

async function pollAnalysis() {
  chrome.storage.local.get({ endpoint: DEFAULT_ENDPOINT }).then(async ({ endpoint }) => {
    try {
      let attempts = 0;
      while (true) {
        if (++attempts > 15) {
          console.warn("Tiempo de espera agotado, continuando navegación.");
          window.location.replace(targetUrl);
          break;
        }
        const response = await fetch(`${endpoint}/${jobId}`);
        if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
        const data = await response.json();
        
        if (data.status === "completed" || data.status === "failed") {
          // Decisión final
          if (data.decision === "phishing") {
            const warningUrl = `warning.html?url=${encodeURIComponent(targetUrl)}&jobId=${jobId}`;
            window.location.replace(warningUrl);
          } else {
            // Seguro, redirigir a la URL original
            // Guardar en la caché local para que NO vuelva a escanearlo nunca más
            chrome.storage.local.get({ allowed_urls: [], safe_url_redirecting: {} }).then(storage => {
               const allowed = storage.allowed_urls;
               // Solo guardar el origen (ej. https://mi-universidad.edu)
               try {
                 const origin = new URL(targetUrl).origin;
                 if (!allowed.includes(origin)) allowed.push(origin);
               } catch(e) {
                 if (!allowed.includes(targetUrl)) allowed.push(targetUrl);
               }
               
               const safeDict = storage.safe_url_redirecting;
               safeDict[targetUrl] = Date.now();
               
               chrome.storage.local.set({ allowed_urls: allowed, safe_url_redirecting: safeDict }, () => {
                 window.location.replace(targetUrl);
               });
            });
          }
          break;
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    } catch (e) {
      console.error(e);
      // En caso de error crítico, dejar pasar o mostrar error
      window.location.replace(targetUrl);
    }
  });
}

if (jobId && targetUrl) {
  pollAnalysis();
} else if (targetUrl) {
  window.location.replace(targetUrl);
}

