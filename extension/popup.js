const endpointInput = document.querySelector("#endpoint");
const state = document.querySelector("#state");
const result = document.querySelector("#result");
const urlLabel = document.querySelector("#url");

function render(payload) {
  const decision = payload.decision || "uncertain";
  const probability = Number(payload.probability_phishing ?? payload.risk_score ?? 0);
  const cls = decision === "phishing" ? "risk-high" : decision === "legitimate" ? "risk-low" : "risk-uncertain";
  result.innerHTML = `<p class="${cls}">${decision} · ${(probability * 100).toFixed(1)}%</p>`;
  if (Array.isArray(payload.evidence_summary)) {
    const list = document.createElement("ul");
    payload.evidence_summary.slice(0, 5).forEach(item => { const li = document.createElement("li"); li.textContent = `${item.feature || item.source}: ${item.value}`; list.appendChild(li); });
    result.appendChild(list);
  }
}

chrome.storage.local.get({ endpoint: "http://localhost:8080/analyses" }).then(({ endpoint }) => { endpointInput.value = endpoint; });
chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
  const url = tab?.url || ""; urlLabel.textContent = url || "URL no disponible";
  document.querySelector("#analyze").onclick = () => {
    state.textContent = "Analizando...";
    chrome.runtime.sendMessage({ type: "analyze", url }, response => {
      if (!response?.ok) { state.textContent = "Error"; result.textContent = response?.error || "No se pudo consultar el backend."; return; }
      state.textContent = "Completado"; render(response.result || {});
    });
  };
});
document.querySelector("#save").onclick = () => chrome.storage.local.set({ endpoint: endpointInput.value.trim() }).then(() => { state.textContent = "Endpoint guardado"; });
