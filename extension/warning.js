const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url');
const jobId = urlParams.get('jobId');

if (targetUrl) {
  document.getElementById('url-display').textContent = targetUrl;
}

document.getElementById('btn-ignore').addEventListener('click', async () => {
  if (targetUrl) {
    chrome.storage.local.get({ allowed_urls: [] }).then(({ allowed_urls }) => {
      allowed_urls.push(targetUrl);
      chrome.storage.local.set({ allowed_urls }, () => {
        window.location.href = targetUrl;
      });
    });
  }
});

document.getElementById('btn-close').addEventListener('click', () => {
  window.close();
});

// Fetch job details to populate probability and rich recommendations
if (jobId) {
  fetch('http://localhost:8080/analyses/' + jobId)
    .then(res => res.json())
    .then(data => {
      if (data.probability !== undefined) {
        document.getElementById('prob-value').textContent = (data.probability * 100).toFixed(1) + '%';
        
        const previewUrl = 'http://localhost:8080/screenshots/' + jobId + '.png';
        const imgTag = '<img src="' + previewUrl + '" style="width: 100%; height: 100%; object-fit: contain; border-radius: 8px;" onerror="this.parentElement.innerHTML=\'Vista previa no disponible\'">';
        document.querySelector('.placeholder-image').innerHTML = imgTag;
        
        // Determinar riesgo
        if (data.probability >= 0.8) {
          document.getElementById('risk-text').textContent = 'ALTO';
          document.getElementById('risk-text').style.color = '#d32f2f';
        } else if (data.probability >= 0.5) {
          document.getElementById('risk-text').textContent = 'MEDIO';
          document.getElementById('risk-text').style.color = '#ed6c02';
        }

        // Buscar los detalles de la IA
        let llmDetails = null;
        if (data.evidence) {
           for (let ev of data.evidence) {
              if (ev.source === "LLM" && ev.details) {
                  llmDetails = ev.details;
                  break;
              }
           }
        }

        if (llmDetails) {
            // Actualizar interfaz con recomendaciones
            if (llmDetails.recommendation) {
                document.getElementById('rec-value').textContent = llmDetails.recommendation;
            }
            if (llmDetails.brand_spoofed && llmDetails.brand_spoofed !== 'Desconocida') {
                document.getElementById('content-badge').textContent = "Similar a " + llmDetails.brand_spoofed;
                document.getElementById('main-title').textContent = "Peligro de suplantación";
            }
            if (llmDetails.reason) {
                document.getElementById('main-desc').innerHTML = "<b>Razón de la IA:</b> " + llmDetails.reason + "<br>Te recomendamos no abrirlo ni ingresar ningún dato personal.";
            }
        } else {
            document.getElementById('rec-value').textContent = "Cierra esta ventana inmediatamente. El sistema ha detectado código malicioso o patrones de phishing agresivos.";
        }
      }
    }).catch(console.error);
}
