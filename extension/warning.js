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

// Fix for CSP: Manejar el botón de cerrar desde JS
document.getElementById('btn-close').addEventListener('click', () => {
  window.close();
});

// Optionally fetch job details to populate probability
if (jobId) {
  fetch('http://localhost:8080/analyses/' + jobId)
    .then(res => res.json())
    .then(data => {
      if (data.probability !== undefined) {
        document.getElementById('prob-value').textContent = (data.probability * 100).toFixed(1) + '%';
        
        // Dynamically update some values based on confidence
        if (data.probability >= 0.8) {
          document.getElementById('content-badge').textContent = 'Alto Riesgo Detectado';
        }
      }
    }).catch(console.error);
}

