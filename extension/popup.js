/**
 * PhishGuard Pro - Extension Popup Controller
 * Manages multimodal inspection, XAI vector rendering, and sandbox actions.
 */

const DEFAULT_ENDPOINT = "http://localhost:8080/check";
let currentTabUrl = "";
let currentJobId = null;

// DOM Elements
const themeToggleBtn = document.getElementById("theme-toggle");
const backendStatus = document.getElementById("backend-status");
const backendStatusText = document.getElementById("backend-status-text");
const countrySelect = document.getElementById("country");

function applyTheme(theme) {
  if (theme === "light") {
    document.documentElement.setAttribute("data-theme", "light");
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
}

const siteHost = document.getElementById("site-host");
const siteUrl = document.getElementById("site-url");
const protocolBadge = document.getElementById("protocol-badge");
const siteProtocol = document.getElementById("site-protocol");
const trancoBadge = document.getElementById("tranco-badge");
const trancoRankText = document.getElementById("tranco-rank-text");
const geoBadge = document.getElementById("geo-badge");
const geoText = document.getElementById("geo-text");

const meterCircle = document.getElementById("meter-circle");
const riskPercentage = document.getElementById("risk-percentage");
const verdictBadge = document.getElementById("verdict-badge");
const verdictModel = document.getElementById("verdict-model");

const recBox = document.getElementById("rec-box");
const recIcon = document.getElementById("rec-icon");
const recHeading = document.getElementById("rec-heading");
const recText = document.getElementById("rec-text");
const smartRecCard = document.getElementById("smart-rec-card");
const smartRecFlag = document.getElementById("smart-rec-flag");
const smartRecDesc = document.getElementById("smart-rec-desc");
const smartRecList = document.getElementById("smart-rec-list");
const diagnosisList = document.getElementById("diagnosis-list");

const valReputation = document.getElementById("val-reputation");
const barReputation = document.getElementById("bar-reputation");
const valBrand = document.getElementById("val-brand");
const barBrand = document.getElementById("bar-brand");
const valLexical = document.getElementById("val-lexical");
const barLexical = document.getElementById("bar-lexical");
const valInfra = document.getElementById("val-infra");
const barInfra = document.getElementById("bar-infra");
const metaSkeleton = document.getElementById("meta-skeleton");
const metaTargetBrand = document.getElementById("meta-target-brand");

const rulesCount = document.getElementById("rules-count");
const rulesList = document.getElementById("rules-list");
const rulesEmpty = document.getElementById("rules-empty");

const btnScan = document.getElementById("btn-scan");
const btnScanText = document.getElementById("btn-scan-text");
const btnSandbox = document.getElementById("btn-sandbox");
const btnDashboard = document.getElementById("btn-dashboard");
const btnManifest = document.getElementById("btn-manifest");

const endpointInput = document.getElementById("endpoint-input");
const btnSaveEndpoint = document.getElementById("btn-save-endpoint");
const btnForgetSite = document.getElementById("btn-forget-site");
const btnClearAll = document.getElementById("btn-clear-all");

// Tab switching
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    const target = document.getElementById(btn.getAttribute("data-tab"));
    if (target) target.classList.add("active");
  });
});

// Check Backend Health
async function checkHealth(endpoint) {
  try {
    const baseUrl = new URL(endpoint).origin;
    const res = await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(2000) });
    if (res.ok) {
      backendStatus.className = "status-pill status-online";
      backendStatusText.textContent = "Online";
      return true;
    }
  } catch (_) {}
  backendStatus.className = "status-pill status-offline";
  backendStatusText.textContent = "Offline";
  return false;
}

// Render Results in UI
function renderPayload(payload) {
  const prob = Number(payload.probability ?? 0);
  const percent = Math.round(prob * 100);
  riskPercentage.textContent = `${percent}%`;

  currentJobId = payload.job_id || null;

  // Meter & Verdict styling
  meterCircle.style.borderColor = "#334155";
  verdictBadge.className = "verdict-badge";

  if (payload.decision === "phishing" || prob >= 0.50) {
    verdictBadge.textContent = "AMENAZA DETECTADA";
    verdictBadge.classList.add("badge-danger");
    meterCircle.style.borderColor = "#ef4444";
    recHeading.textContent = "Peligro de Suplantación";
    recIcon.textContent = "🚨";
    recText.textContent = "Este sitio presenta indicios de phishing o fraude. No ingreses datos personales, contraseñas ni números de tarjeta.";
    recBox.style.borderLeftColor = "#ef4444";
  } else if (payload.decision === "warning" || prob >= 0.30) {
    const hasLocalSug = Boolean(payload.local_suggestions && payload.local_suggestions.length > 0);
    verdictBadge.textContent = hasLocalSug ? "PRECAUCIÓN REGIONAL" : "SOSPECHOSO";
    verdictBadge.classList.add("badge-warning");
    meterCircle.style.borderColor = "#f59e0b";
    recHeading.textContent = hasLocalSug ? "Posible Confusión de Entidad" : "Procede con Cautela";
    recIcon.textContent = "⚠️";
    recText.textContent = hasLocalSug
      ? "Este dominio opera en el extranjero y coincide con marcas de tu país. Te sugerimos acceder directamente a la entidad oficial recomendada."
      : "Se detectaron anomalías o posible desajuste regional. Verifica la URL antes de suministrar credenciales.";
    recBox.style.borderLeftColor = "#f59e0b";
  } else {
    verdictBadge.textContent = "DOMINIO AUTÉNTICO";
    verdictBadge.classList.add("badge-safe");
    meterCircle.style.borderColor = "#10b981";
    recHeading.textContent = "Sitio Confiable";
    recIcon.textContent = "🛡️";
    recText.textContent = "El dominio cuenta con infraestructura legítima y no presenta características de suplantación conocidas.";
    recBox.style.borderLeftColor = "#10b981";
  }

  verdictModel.textContent = payload.model || "PhishGuard Multimodal M0+Tranco";

  // Tranco Chip
  const rep = payload.reputation || {};
  if (rep.tranco_rank) {
    trancoRankText.textContent = `#${rep.tranco_rank.toLocaleString()} Tranco Global`;
    trancoBadge.style.color = "#10b981";
  } else if (rep.reputation_label) {
    trancoRankText.textContent = rep.reputation_label;
    trancoBadge.style.color = "#38bdf8";
  } else {
    trancoRankText.textContent = "Sin Tranco Rank";
    trancoBadge.style.color = "#94a3b8";
  }

  // Geo Origin Badge
  const geo = payload.geo_context;
  if (geo && (geo.origin_country || geo.origin_country_name) && geo.origin_country !== "UNKNOWN") {
    geoBadge.style.display = "flex";
    const originName = geo.origin_country_name || geo.origin_country;
    const userName = geo.user_country_name || geo.user_country;

    if (geo.is_foreign) {
      geoBadge.className = "geo-badge geo-foreign";
      if (userName && userName !== originName) {
        geoText.textContent = `Servidor en ${originName} (${geo.origin_country}) · Tu país: ${userName}`;
      } else {
        geoText.textContent = `Servidor alojado en ${originName} (${geo.origin_country})`;
      }
    } else {
      geoBadge.className = "geo-badge";
      geoText.textContent = `Servidor local en ${originName} (${geo.origin_country})`;
    }
  } else {
    geoBadge.style.display = "none";
  }

  // Smart Local Navigation Recommendations
  const suggestions = payload.local_suggestions || [];
  if (suggestions.length > 0) {
    smartRecCard.style.display = "block";
    const userCountryName = geo?.user_country_name || geo?.user_country || "tu país";
    smartRecFlag.textContent = `📍 ${userCountryName}`;
    smartRecList.innerHTML = "";

    suggestions.forEach(s => {
      const item = document.createElement("div");
      item.className = "smart-rec-item";
      item.innerHTML = `
        <div class="smart-rec-item-info">
          <div class="smart-rec-brand-name">${s.brand_name}</div>
          <div class="smart-rec-reason">${s.reason}</div>
        </div>
        <button class="smart-rec-btn" data-url="${s.url}" title="Ir a ${s.url}">
          <span>${s.suggested_domain}</span>
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        </button>
      `;

      item.querySelector(".smart-rec-btn").addEventListener("click", (e) => {
        e.stopPropagation();
        chrome.tabs.create({ url: s.url });
      });

      smartRecList.appendChild(item);
    });
  } else {
    smartRecCard.style.display = "none";
  }

  // Bullets
  diagnosisList.innerHTML = "";
  const bullets = [];
  if (rep.tranco_rank && rep.tranco_rank <= 50000) {
    bullets.push(`Dominio verificado en Tranco Top ${rep.tranco_rank.toLocaleString()} de máxima prevalencia mundial.`);
  } else if (rep.tranco_rank) {
    bullets.push(`Dominio listado en el ranking global Tranco (#${rep.tranco_rank.toLocaleString()}).`);
  } else {
    bullets.push("Dominio sin ranking Tranco global: tráfico o registro reciente.");
  }

  if (geo?.is_foreign && geo.origin_country_name) {
    bullets.push(`Infraestructura extranjera: servidor alojado en ${geo.origin_country_name} (${geo.origin_country}).`);
  }

  if (suggestions.length > 0) {
    bullets.push(`Sugerencia de navegación: similar a "${suggestions[0].brand_name}" (${suggestions[0].suggested_domain}).`);
  }

  if (payload.homoglyphs?.is_spoofing) {
    bullets.push(`ALERTA: Se detectó ataque homográfico simulando la marca ${payload.homoglyphs.target_brand}.`);
  }

  if (payload.brand_analysis?.is_brand_impersonation) {
    bullets.push(`Posible suplantación léxica de la marca "${payload.brand_analysis.closest_brand}".`);
  }

  if (payload.brand_mismatch) {
    bullets.push(`Desajuste marca-país: marca regional detectada en infraestructura foránea.`);
  }

  const triggeredRules = payload.rules_analysis?.triggered_rules || [];
  if (triggeredRules.length > 0) {
    bullets.push(`Reglas técnicas activadas: ${triggeredRules.map(r => r.rule).join(", ")}.`);
  } else {
    bullets.push("Estructura de certificados, TLD y enlaces conforme a estándares.");
  }

  bullets.forEach(b => {
    const li = document.createElement("li");
    li.textContent = b;
    diagnosisList.appendChild(li);
  });

  // XAI Breakdown
  const rb = payload.risk_breakdown || {};
  const repRisk = rb.reputation_risk ?? (rep.trust_score ? Math.round((1 - rep.trust_score) * 100) : 50);
  const brandRisk = rb.brand_risk ?? (payload.brand_analysis ? Math.round((payload.brand_analysis.typosquatting_score || 0) * 100) : 0);
  const lexicalRisk = rb.lexical ?? Math.round(Number(payload.m0_probability || 0) * 100);
  const infraRisk = rb.infrastructure_risk ?? Math.round((payload.rules_analysis?.aggregate_score || 0) * 100);

  valReputation.textContent = `${repRisk}%`;
  barReputation.style.width = `${repRisk}%`;
  valBrand.textContent = `${brandRisk}%`;
  barBrand.style.width = `${brandRisk}%`;
  valLexical.textContent = `${lexicalRisk}%`;
  barLexical.style.width = `${lexicalRisk}%`;
  valInfra.textContent = `${infraRisk}%`;
  barInfra.style.width = `${infraRisk}%`;

  metaSkeleton.textContent = payload.homoglyphs?.visual_skeleton || rep.host || "--";
  metaTargetBrand.textContent = payload.homoglyphs?.target_brand || payload.brand_analysis?.closest_brand || "Ninguna";

  // Rules List
  rulesCount.textContent = triggeredRules.length;
  rulesList.innerHTML = "";
  if (triggeredRules.length === 0) {
    rulesEmpty.style.display = "block";
  } else {
    rulesEmpty.style.display = "none";
    triggeredRules.forEach(r => {
      const item = document.createElement("div");
      item.className = "rule-item";
      const sevClass = r.confidence >= 0.7 ? "severity-high" : r.confidence >= 0.4 ? "severity-med" : "severity-low";
      const sevLabel = r.confidence >= 0.7 ? "Alto" : r.confidence >= 0.4 ? "Medio" : "Bajo";
      item.innerHTML = `
        <div class="rule-header">
          <span class="rule-name">${r.rule.replace(/_/g, " ")}</span>
          <span class="rule-severity ${sevClass}">${sevLabel} (${Math.round(r.confidence * 100)}%)</span>
        </div>
        <div class="rule-reason">${r.reason || "Patrón anómalo"}</div>
      `;
      rulesList.appendChild(item);
    });
  }
}

// Extracts the actual inspected URL if we are currently looking at warning.html
function extractRealTargetUrl(rawUrl) {
  if (!rawUrl) return "";
  
  if (rawUrl.includes("warning.html") && rawUrl.includes("url=")) {
    try {
      const parsed = new URL(rawUrl);
      const target = parsed.searchParams.get("url");
      const passedJobId = parsed.searchParams.get("jobId");
      if (passedJobId) {
        currentJobId = passedJobId;
      }
      if (target) {
        return decodeURIComponent(target);
      }
    } catch (_) {}
  }
  
  return rawUrl;
}

// Run Analysis
async function performAnalysis(url, force = false) {
  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
    siteHost.textContent = "Pestaña no analizable";
    siteUrl.textContent = url || "about:blank";
    trancoRankText.textContent = "URL interna";
    return;
  }

  btnScanText.textContent = "Escaneando...";
  btnScan.disabled = true;

  chrome.runtime.sendMessage({ type: "analyze", url, force }, response => {
    btnScanText.textContent = "Re-escanear Pestaña";
    btnScan.disabled = false;

    if (!response?.ok) {
      recHeading.textContent = "Error al Analizar";
      recText.textContent = response?.error || "No se pudo comunicar con el backend local PhishGuard.";
      recIcon.textContent = "⚠️";
      verdictBadge.textContent = "ERROR CONEXIÓN";
      verdictBadge.className = "verdict-badge badge-warning";
      return;
    }

    renderPayload(response.result || {});
  });
}

// Initial Setup
document.addEventListener("DOMContentLoaded", async () => {
  const { endpoint, user_country, theme } = await chrome.storage.local.get({
    endpoint: DEFAULT_ENDPOINT,
    user_country: "",
    theme: "dark"
  });

  applyTheme(theme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener("click", async () => {
      const isLight = document.documentElement.getAttribute("data-theme") === "light";
      const newTheme = isLight ? "dark" : "light";
      applyTheme(newTheme);
      await chrome.storage.local.set({ theme: newTheme });
    });
  }

  const normalizedEndpoint = (endpoint && !endpoint.includes("/analyses")) ? endpoint : DEFAULT_ENDPOINT;
  endpointInput.value = normalizedEndpoint;
  if (user_country) countrySelect.value = user_country;

  await checkHealth(normalizedEndpoint);

  // Load Active Tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) {
    const rawUrl = tab.url;
    const isWarningPage = rawUrl.includes("warning.html");
    const targetUrl = extractRealTargetUrl(rawUrl);
    currentTabUrl = targetUrl;

    if (!targetUrl || (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://"))) {
      siteHost.textContent = "Pestaña del Sistema";
      siteUrl.textContent = rawUrl || "Página interna de Chrome";
      trancoRankText.textContent = "Navegación Local";
      verdictBadge.textContent = "SISTEMA";
      verdictBadge.className = "verdict-badge badge-neutral";
      meterCircle.style.borderColor = "#475569";
      riskPercentage.textContent = "0%";
      recHeading.textContent = "Pestaña Interna";
      recIcon.textContent = "ℹ️";
      recText.textContent = "Esta página es interna del navegador o extensión y no representa un destino web público.";
      btnScan.disabled = true;
      btnScanText.textContent = "No Aplica Escaneo";
      return;
    }

    siteUrl.textContent = targetUrl;

    try {
      const parsed = new URL(targetUrl);
      siteHost.textContent = parsed.hostname;
      siteProtocol.textContent = parsed.protocol.replace(":", "").toUpperCase();
      if (parsed.protocol === "http:") {
        protocolBadge.className = "protocol-badge protocol-insecure";
      } else {
        protocolBadge.className = "protocol-badge";
      }
    } catch (_) {
      siteHost.textContent = targetUrl;
    }

    if (isWarningPage) {
      trancoRankText.textContent = "🚨 Sitio Bloqueado";
      trancoBadge.style.color = "#ef4444";
    }

    // Auto-analyze real target URL
    performAnalysis(currentTabUrl);
  }

  // Scan Button
  btnScan.addEventListener("click", () => {
    performAnalysis(currentTabUrl, true);
  });

  // Country select change
  countrySelect.addEventListener("change", () => {
    const val = countrySelect.value;
    chrome.storage.local.set({ user_country: val }).then(() => {
      performAnalysis(currentTabUrl, true);
    });
  });

  // Sandbox Button
  btnSandbox.addEventListener("click", () => {
    const baseUrl = new URL(endpointInput.value.trim() || DEFAULT_ENDPOINT).origin;
    if (currentJobId) {
      chrome.tabs.create({ url: `${baseUrl}/previews/${currentJobId}` });
    } else if (currentTabUrl) {
      // Si aún no hay jobId, podemos abrir el dashboard con la URL
      chrome.tabs.create({ url: `${baseUrl}/dashboard` });
    }
  });

  // Dashboard Button
  btnDashboard.addEventListener("click", () => {
    const baseUrl = new URL(endpointInput.value.trim() || DEFAULT_ENDPOINT).origin;
    chrome.tabs.create({ url: `${baseUrl}/dashboard` });
  });

  // Forensic Manifest Button
  btnManifest.addEventListener("click", () => {
    const baseUrl = new URL(endpointInput.value.trim() || DEFAULT_ENDPOINT).origin;
    if (currentJobId) {
      chrome.tabs.create({ url: `${baseUrl}/jobs/${currentJobId}/forensic-manifest` });
    } else {
      alert("Realiza un escaneo primero para generar el identificador forense.");
    }
  });

  // Save Endpoint
  btnSaveEndpoint.addEventListener("click", () => {
    const ep = endpointInput.value.trim();
    chrome.storage.local.set({ endpoint: ep }).then(() => {
      checkHealth(ep);
    });
  });

  // Forget Site Exception
  btnForgetSite.addEventListener("click", () => {
    if (!currentTabUrl) return;
    try {
      const origin = new URL(currentTabUrl).origin;
      chrome.storage.local.get({ allowed_urls: [] }).then(({ allowed_urls }) => {
        const filtered = (allowed_urls || []).filter(item => {
          if (typeof item === 'string') return item !== origin;
          return item.origin !== origin;
        });
        chrome.storage.local.set({ allowed_urls: filtered }).then(() => {
          alert(`Excepción eliminada para ${origin}. Se volverá a auditar.`);
          performAnalysis(currentTabUrl, true);
        });
      });
    } catch (_) {}
  });

  // Clear All Exceptions
  btnClearAll.addEventListener("click", () => {
    if (confirm("¿Estás seguro de que deseas limpiar todas las excepciones guardadas?")) {
      chrome.storage.local.set({ allowed_urls: [], safe_url_redirecting: {} }).then(() => {
        alert("Todas las excepciones han sido restablecidas.");
        performAnalysis(currentTabUrl, true);
      });
    }
  });
});
