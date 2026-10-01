/**
 * PhishGuard Pro - Warning & Interception Controller
 * Manages cybersecurity triage, regional collision explanations, and isolation runtime.
 */

const urlParams = new URLSearchParams(window.location.search);
let targetUrl = urlParams.get('url');
const jobId = urlParams.get('jobId');
const isPending = urlParams.get('pending') === 'true';
let probability = urlParams.get('probability');
let decisionType = (urlParams.get('decision') || 'phishing');
const bmName = urlParams.get('bm_name') || '';
const bmDomain = urlParams.get('bm_domain') || '';
const bmCategory = urlParams.get('bm_category') || '';
const bmSuggestion = urlParams.get('bm_suggestion') || '';
const bmDifferentEntity = urlParams.get('bm_diff') === '1';
const hasBmData = Boolean(bmName && bmDomain);

// Theme Support (Light / Dark Mode)
function applyTheme(theme) {
  if (theme === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
  } else {
    document.documentElement.removeAttribute('data-theme');
  }
}

if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
  chrome.storage.local.get({ theme: 'dark' }).then(({ theme }) => {
    applyTheme(theme);
  });
}

function setupThemeToggle() {
  const themeToggle = document.getElementById('theme-toggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', async () => {
      const isLight = document.documentElement.getAttribute('data-theme') === 'light';
      const newTheme = isLight ? 'dark' : 'light';
      applyTheme(newTheme);
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        await chrome.storage.local.set({ theme: newTheme });
      }
    });
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', setupThemeToggle);
} else {
  setupThemeToggle();
}

// PENDING MODE: backend is still processing, show spinner and poll
if (isPending && targetUrl) {
  document.addEventListener('DOMContentLoaded', () => {
    const banner = document.querySelector('.warning-banner');
    if (banner) {
      banner.style.borderColor = 'rgba(56, 189, 248, 0.4)';
      banner.style.boxShadow = '0 0 24px rgba(56, 189, 248, 0.15)';
    }
    const iconWrap = document.querySelector('.warning-icon-wrap');
    if (iconWrap) {
      iconWrap.style.background = 'rgba(56, 189, 248, 0.15)';
      iconWrap.style.color = '#38bdf8';
      iconWrap.style.borderColor = 'rgba(56, 189, 248, 0.4)';
      iconWrap.innerHTML = '<div class="spinner"></div>';
    }
    document.getElementById('main-title').textContent = 'Analizando sitio con IA Forense...';
    document.getElementById('main-desc').textContent = 'PhishGuard Pro está auditando la infraestructura, TLD, certificados y huella semántica de este enlace. Esto tomará un momento.';
    
    const badge = document.querySelector('.url-status-badge');
    if (badge) {
      badge.textContent = '⏳ Inspección en curso';
      badge.style.background = 'rgba(56, 189, 248, 0.12)';
      badge.style.color = '#38bdf8';
      badge.style.borderColor = 'rgba(56, 189, 248, 0.3)';
    }
    
    document.querySelector('.page-subtitle').textContent = 'Evaluación multimodal en tiempo real contra Tranco Top 1M y modelos M0/Brand.';
    document.getElementById('btn-close').style.display = 'none';
    document.getElementById('btn-ignore').style.display = 'none';
    document.getElementById('url-display').textContent = targetUrl;

    const scenariosCard = document.getElementById('scenarios-card');
    if (scenariosCard) scenariosCard.style.display = 'none';
    const recBanner = document.querySelector('.rec-banner');
    if (recBanner) recBanner.style.display = 'none';

    // Poll for result
    const resultKey = `result_${targetUrl}`;
    const rulesKey = `rules_${targetUrl}`;
    const bmKey = `brand_mismatch_${targetUrl}`;
    let attempts = 0;
    const poll = setInterval(async () => {
      attempts++;
      if (attempts > 60) { clearInterval(poll); return; }
      try {
        const data = await chrome.storage.local.get([resultKey, rulesKey, bmKey]);
        const result = data[resultKey];
        if (result?.ready) {
          clearInterval(poll);
          const newParams = new URLSearchParams({
            url: targetUrl,
            probability: result.probability,
            decision: result.decision
          });
          const bmData = data[bmKey];
          if (bmData) {
            newParams.set('bm_name', bmData.brand_full_name || '');
            newParams.set('bm_domain', bmData.local_domain || '');
            newParams.set('bm_category', bmData.category || '');
            newParams.set('bm_suggestion', bmData.suggestion || '');
            if (bmData.is_different_entity) newParams.set('bm_diff', '1');
          }
          window.location.search = newParams.toString();
        }
      } catch (e) {
        console.error('[PhishGuard] Poll error:', e);
      }
    }, 500);
  });
}

// === NORMAL MODE ===
if (!isPending) {
  // Setup URLs and initial DOM
  if (targetUrl) {
    document.getElementById('url-display').textContent = targetUrl;
    try {
      const u = new URL(targetUrl);
      document.getElementById('domain-val').textContent = u.hostname;
      const isHttps = u.protocol === 'https:';
      const sslEl = document.getElementById('ssl-val');
      sslEl.textContent = isHttps ? 'HTTPS Cifrado' : 'HTTP No Seguro';
      sslEl.className = isHttps ? 'badge badge-success' : 'badge badge-danger';
    } catch (e) {
      document.getElementById('domain-val').textContent = targetUrl;
    }
    loadRulesData(targetUrl);
  }

  // Initial UI styling based on decisionType
  applyDecisionStyling();

  // Button actions
  setupActionButtons();

  // Load telemetry data
  if (probability) {
    populateWithCheckData(parseFloat(probability), targetUrl);
  } else if (jobId) {
    const endpoint = 'http://localhost:8080/analyses';
    fetch(`${endpoint}/${jobId}`)
      .then(res => {
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        return res.json();
      })
      .then(data => {
        if (data.url) {
          targetUrl = targetUrl || data.url;
          document.getElementById('url-display').textContent = data.url;
          try {
            const u = new URL(data.url);
            document.getElementById('domain-val').textContent = u.hostname;
            const isHttps = u.protocol === 'https:';
            const sslEl = document.getElementById('ssl-val');
            sslEl.textContent = isHttps ? 'HTTPS Cifrado' : 'HTTP No Seguro';
            sslEl.className = isHttps ? 'badge badge-success' : 'badge badge-danger';
          } catch (_) {}
        }
        const prob = Number(data.probability ?? 1.0);
        populateWithCheckData(prob, data.url || targetUrl);
      })
      .catch(() => {
        populateWithCheckData(1.0, targetUrl);
      });
  } else {
    populateWithCheckData(1.0, targetUrl);
  }
}

// Applies High-End Styling according to verdict
function applyDecisionStyling() {
  const banner = document.querySelector('.warning-banner');
  const iconWrap = document.querySelector('.warning-icon-wrap');
  const statusBadge = document.querySelector('.url-status-badge');
  const subtitle = document.querySelector('.page-subtitle');
  const actionCard = document.getElementById('action-rec-card');

  if (decisionType === 'legitimate') {
    if (banner) {
      banner.style.borderColor = 'rgba(16, 185, 129, 0.4)';
      banner.style.boxShadow = '0 0 24px rgba(16, 185, 129, 0.12)';
    }
    if (iconWrap) {
      iconWrap.style.background = 'rgba(16, 185, 129, 0.15)';
      iconWrap.style.borderColor = 'rgba(16, 185, 129, 0.4)';
      iconWrap.style.color = '#34d399';
      iconWrap.textContent = '✓';
    }
    document.getElementById('main-title').textContent = 'Dominio Verificado / Seguro';
    document.getElementById('main-desc').textContent = 'Este sitio cuenta con infraestructura legítima verificada y no presenta indicios de suplantación. Puedes navegar con normalidad.';
    if (statusBadge) {
      statusBadge.textContent = '✓ Seguro';
      statusBadge.style.background = 'rgba(16, 185, 129, 0.12)';
      statusBadge.style.color = '#34d399';
      statusBadge.style.borderColor = 'rgba(16, 185, 129, 0.3)';
    }
    if (subtitle) subtitle.textContent = 'Análisis completado: el destino cumple con las pautas de integridad.';
    const btnClose = document.getElementById('btn-close');
    btnClose.innerHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
      Continuar al sitio seguro
    `;
    btnClose.style.background = 'linear-gradient(135deg, #10b981, #059669)';
    document.getElementById('btn-ignore').textContent = 'Volver atrás';
    return;
  }

  if (decisionType === 'warning') {
    if (banner) {
      banner.style.borderColor = 'rgba(245, 158, 11, 0.45)';
      banner.style.boxShadow = '0 0 24px rgba(245, 158, 11, 0.12)';
    }
    if (iconWrap) {
      iconWrap.style.background = 'rgba(245, 158, 11, 0.15)';
      iconWrap.style.borderColor = 'rgba(245, 158, 11, 0.4)';
      iconWrap.style.color = '#fbbf24';
      iconWrap.textContent = '⚠';
    }
    if (statusBadge) {
      statusBadge.textContent = '⚠️ Precaución Regional';
      statusBadge.style.background = 'rgba(245, 158, 11, 0.15)';
      statusBadge.style.color = '#fbbf24';
      statusBadge.style.borderColor = 'rgba(245, 158, 11, 0.35)';
    }

    const hostname = (() => { try { return new URL(targetUrl).hostname; } catch(_) { return targetUrl; } })();

    if (bmName && bmDomain) {
      if (bmDifferentEntity) {
        document.getElementById('main-title').textContent = `Precaución: Dominio no vinculado a ${bmName}`;
        document.getElementById('main-desc').textContent = `Has intentado acceder a "${hostname}". Este dominio es un sitio foráneo independiente y NO pertenece a ${bmName}, aunque coincide en sus siglas. Si buscabas tu entidad bancaria en tu país, debes dirigirte a ${bmDomain}.`;
        if (subtitle) subtitle.textContent = `Pausa preventiva: detectada colisión de siglas con ${bmName} (sitio oficial: ${bmDomain}).`;
      } else {
        document.getElementById('main-title').textContent = `Advertencia: Versión Regional de ${bmName}`;
        document.getElementById('main-desc').textContent = `Estás visitando el portal oficial de ${bmName} para otra región. Si tus cuentas fueron contratadas en tu país local, debes operar desde ${bmDomain}.`;
        if (subtitle) subtitle.textContent = `Desajuste de jurisdicción bancaria respecto a tu país configurado.`;
      }

      // Show Action Recommendation Card
      if (actionCard) {
        actionCard.style.display = 'flex';
        document.getElementById('action-rec-name').textContent = bmName;
        document.getElementById('btn-official-text').textContent = `Ir al sitio oficial seguro (${bmDomain}) ↗`;
      }
    } else {
      document.getElementById('main-title').textContent = 'Advertencia: Dominio fuera de tu región';
      document.getElementById('main-desc').textContent = `El dominio "${hostname}" opera en una región foránea y presenta características que requieren precaución antes de interactuar.`;
      if (subtitle) subtitle.textContent = 'Análisis geográfico y de reputación detectó inconsistencias de ubicación.';
    }

    const btnClose = document.getElementById('btn-close');
    const targetBtnText = bmDomain ? `Ir al sitio oficial (${bmDomain})` : 'Cerrar pestaña (Seguro)';
    btnClose.innerHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
      ${targetBtnText}
    `;
    btnClose.style.background = 'linear-gradient(135deg, #0284c7, #0369a1)';
    btnClose.style.boxShadow = '0 0 16px rgba(2, 132, 199, 0.35)';

    document.getElementById('btn-ignore').textContent = `Continuar a ${hostname} de todos modos (No recomendado para banca)`;
    return;
  }

  // PHISHING / ATTACK
  if (banner) {
    banner.style.borderColor = 'rgba(239, 68, 68, 0.45)';
    banner.style.boxShadow = '0 0 28px rgba(239, 68, 68, 0.2)';
  }
  if (iconWrap) {
    iconWrap.style.background = 'rgba(239, 68, 68, 0.15)';
    iconWrap.style.borderColor = 'rgba(239, 68, 68, 0.4)';
    iconWrap.style.color = '#ef4444';
    iconWrap.textContent = '!';
  }
}

// Setup Event Listeners for Actions
function setupActionButtons() {
  const btnClose = document.getElementById('btn-close');
  const btnIgnore = document.getElementById('btn-ignore');
  const btnGoOfficial = document.getElementById('btn-go-official');

  // Navigate to official domain helper
  const navigateToOfficial = () => {
    if (bmDomain) {
      const target = bmDomain.startsWith('http') ? bmDomain : `https://${bmDomain}`;
      window.location.href = target;
      return;
    }
    // Storage fallback
    const storageKey = `rules_${targetUrl}`;
    const brandMismatchKey = `brand_mismatch_${targetUrl}`;
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      chrome.storage.local.get([storageKey, brandMismatchKey]).then(data => {
        const bm = data[brandMismatchKey];
        if (bm?.local_domain) {
          const target = bm.local_domain.startsWith('http') ? bm.local_domain : `https://${bm.local_domain}`;
          window.location.href = target;
        } else {
          window.close();
        }
      }).catch(() => window.close());
    } else {
      window.close();
    }
  };

  if (btnGoOfficial) {
    btnGoOfficial.addEventListener('click', (e) => {
      e.preventDefault();
      navigateToOfficial();
    });
  }

  if (btnClose) {
    btnClose.addEventListener('click', () => {
      if (decisionType === 'warning' && bmDomain) {
        navigateToOfficial();
        return;
      }
      if (decisionType === 'legitimate' && targetUrl) {
        window.location.href = targetUrl;
        return;
      }
      // Phishing: close tab
      try {
        if (typeof chrome !== 'undefined' && chrome.tabs?.getCurrent) {
          chrome.tabs.getCurrent(tab => {
            if (tab?.id) chrome.tabs.remove(tab.id);
            else window.close();
          });
        } else {
          window.close();
        }
      } catch (_) {
        window.close();
      }
    });
  }

  if (btnIgnore) {
    btnIgnore.addEventListener('click', () => {
      const finalUrl = targetUrl || document.getElementById('url-display').textContent;
      if (!finalUrl || finalUrl.startsWith('Cargando')) return;

      if (typeof chrome !== 'undefined' && chrome.storage?.local) {
        chrome.storage.local.get({ allowed_urls: [] }).then(({ allowed_urls }) => {
          const allowed = allowed_urls || [];
          try {
            const origin = new URL(finalUrl).origin;
            if (!allowed.some(e => (typeof e === 'string' ? e === origin : e.origin === origin))) {
              allowed.push({ origin, timestamp: Date.now() });
            }
          } catch (_) {
            if (!allowed.some(e => (typeof e === 'string' ? e === finalUrl : e.origin === finalUrl))) {
              allowed.push({ origin: finalUrl, timestamp: Date.now() });
            }
          }
          chrome.storage.local.set({ allowed_urls: allowed }, () => {
            window.location.href = finalUrl;
          });
        });
      } else {
        window.location.href = finalUrl;
      }
    });
  }
}

// Extract closest brand
function extractBrandFromUrl(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, '');
    const domain = hostname.split('.')[0];
    const brands = [
      'facebook','google','microsoft','apple','amazon','paypal','netflix',
      'instagram','whatsapp','twitter','linkedin','github','bbva','bcp',
      'santander','hsbc','scotiabank','interbank','banco','falabella','ripley'
    ];
    for (const b of brands) {
      if (domain === b || domain.includes(b)) {
        return b.toUpperCase();
      }
    }
  } catch (_) {}
  return null;
}

// Populate UI with check data
function populateWithCheckData(prob, url) {
  const probPct = (prob * 100).toFixed(1) + '%';
  const isWarning = decisionType === 'warning';

  document.getElementById('prob-val').textContent = probPct;
  document.getElementById('risk-pct-banner').textContent = probPct;

  const riskEl = document.getElementById('risk-text');
  if (isWarning) {
    riskEl.textContent = 'PRECAUCIÓN';
    riskEl.style.color = '#f59e0b';
  } else if (prob >= 0.8) {
    riskEl.textContent = 'CRÍTICO';
    riskEl.style.color = '#ef4444';
  } else if (prob >= 0.5) {
    riskEl.textContent = 'MEDIO';
    riskEl.style.color = '#f59e0b';
  } else {
    riskEl.textContent = 'BAJO';
    riskEl.style.color = '#10b981';
  }

  const brand = extractBrandFromUrl(url);
  const hostname = (() => { try { return new URL(url).hostname; } catch(_) { return url; } })();

  if (isWarning) {
    if (bmDifferentEntity && bmName) {
      document.getElementById('brand-val').textContent = `${bmName} (Entidad Local)`;
      document.getElementById('brand-val').className = 'badge badge-warning';
      document.getElementById('threat-val').textContent = 'Colisión de Siglas / No Vinculado';
      document.getElementById('threat-val').className = 'badge badge-warning';
      document.getElementById('why-percentage-desc').textContent =
        `El dominio foráneo "${hostname}" coincide con las siglas de ${bmName}. Para prevenir desvíos y robo de credenciales, el sistema detuvo la navegación.`;
    } else if (hasBmData) {
      document.getElementById('brand-val').textContent = `${bmName} (Filial Foránea)`;
      document.getElementById('brand-val').className = 'badge badge-warning';
      document.getElementById('threat-val').textContent = 'Portal Oficial de otra Región';
      document.getElementById('threat-val').className = 'badge badge-warning';
      document.getElementById('why-percentage-desc').textContent =
        `Estás en la filial oficial de ${bmName} para otra jurisdicción. Tus cuentas locales se administran en ${bmDomain}.`;
    } else {
      document.getElementById('brand-val').textContent = brand || 'Marca no asociada';
      document.getElementById('brand-val').className = 'badge badge-warning';
      document.getElementById('threat-val').textContent = 'Dominio fuera de tu región';
      document.getElementById('threat-val').className = 'badge badge-warning';
      document.getElementById('why-percentage-desc').textContent =
        `El dominio opera en una infraestructura foránea y no corresponde al portal oficial de tu país.`;
    }
  } else {
    if (brand) {
      document.getElementById('brand-val').textContent = brand;
      document.getElementById('threat-val').textContent = `Suplantación de ${brand} (Phishing)`;
      document.getElementById('main-title').textContent = `Peligro: Suplantación de ${brand}`;
      document.getElementById('main-desc').innerHTML = `El dominio <strong>${hostname}</strong> presenta indicadores de suplantación maliciosa de <strong>${brand}</strong>. No ingreses credenciales ni datos personales.`;
    } else {
      document.getElementById('brand-val').textContent = 'Dominio de riesgo genérico';
      document.getElementById('threat-val').textContent = 'Sitio sospechoso de fraude digital';
    }
  }
}

// Build accurate purpose explanation
function buildPurpose(url, brand, allRules, brandMismatch, decisionType) {
  const hostname = (() => { try { return new URL(url).hostname; } catch(_) { return url; } })();
  const geoRule = allRules.find(r => r.rule === 'server_geolocation');
  const serverCountry = geoRule?.details?.country || 'el extranjero';

  const bm = brandMismatch;
  const mismatchRule = allRules.find(r => r.rule === 'brand_country_mismatch');
  const brandMatch = bm || (mismatchRule?.triggered ? mismatchRule.details : null);
  const isDiff = bmDifferentEntity || brandMatch?.is_different_entity;

  if (decisionType === 'warning') {
    const name = brandMatch?.brand_full_name || bmName;
    const dom = brandMatch?.local_domain || bmDomain;

    if (isDiff && name) {
      return `Sitio web internacional independiente alojado en ${serverCountry}. NO mantiene relación formal ni operativa con ${name}. Se ha pausado la navegación para advertirte que este no es el portal bancario de tu país (${dom}) y evitar la exposición involuntaria de credenciales.`;
    }
    if (brandMatch) {
      return `Filial regional legítima de ${name} para otra jurisdicción. Si resides en tu país local, tus operaciones bancarias y cuentas deben gestionarse a través del portal oficial ${dom}.`;
    }
    return `Dominio foráneo con servidor en ${serverCountry}. Se activó la precaución preventiva debido a discrepancias geográficas respecto a tu ubicación.`;
  }

  if (brand) {
    return `Portal sospechoso con indicios de suplantación de la marca "${brand}". Diseñado para imitar la interfaz del servicio y capturar credenciales de acceso o datos bancarios mediante engaño.`;
  }

  return `Portal clasificado como de alto riesgo por el motor multimodal de detección. Se recomienda abstenerse de ingresar información personal o credenciales.`;
}

// Build accurate scenarios
function buildScenarios(url, brand, allRules, brandMismatch, decisionType) {
  const scenarios = [];
  const hostname = (() => { try { return new URL(url).hostname; } catch(_) { return url; } })();
  const geoRule = allRules.find(r => r.rule === 'server_geolocation');
  const serverCountry = geoRule?.details?.country || 'el extranjero';
  const serverIsp = geoRule?.details?.isp || 'ISP externo';

  const bm = brandMismatch;
  const mismatchRule = allRules.find(r => r.rule === 'brand_country_mismatch');
  const brandMatch = bm || (mismatchRule?.triggered ? mismatchRule.details : null);
  const isDiff = bmDifferentEntity || brandMatch?.is_different_entity;

  if (decisionType === 'warning') {
    const name = brandMatch?.brand_full_name || bmName || 'tu entidad bancaria';
    const localDom = brandMatch?.local_domain || bmDomain || 'el portal oficial';

    if (isDiff) {
      scenarios.push({
        title: `Prevención de desvío y robo de credenciales`,
        desc: `Al ingresar a "${hostname}", podrías confundir este portal con ${name} por similitud de siglas o término. No ingreses claves web, números de tarjeta ni tokens en este sitio.`,
        highlight: true
      });
      scenarios.push({
        title: `Infraestructura foránea en ${serverCountry}`,
        desc: `Este dominio resuelve a servidores ubicados en ${serverCountry} (${serverIsp}), fuera de la supervisión de los organismos financieros reguladores de tu país.`,
        highlight: false
      });
      scenarios.push({
        title: `Canal oficial certificado en tu país`,
        desc: `Para gestionar tus cuentas o servicios de ${name} con total respaldo de seguridad, ingresa siempre de forma directa a ${localDom}.`,
        highlight: false
      });
    } else {
      scenarios.push({
        title: `Filial oficial de otra jurisdicción`,
        desc: `Estás en el portal oficial de ${name} para otra región. Tus productos financieros locales no son administrables desde esta plataforma foránea.`,
        highlight: true
      });
      scenarios.push({
        title: `Acceso al portal local certificado`,
        desc: `Ingresa a ${localDom} para iniciar sesión en tu banca por internet local de forma segura.`,
        highlight: false
      });
    }
    return scenarios;
  }

  // Phishing scenarios
  if (brand) {
    scenarios.push({
      title: `Suplantación maliciosa de ${brand}`,
      desc: `El dominio "${hostname}" imita la identidad de ${brand} mediante técnicas de engaño tipográfico (typosquatting).`,
      highlight: true
    });
  }

  const financialRule = allRules.find(r => r.rule === 'financial_phishing');
  if (financialRule?.triggered && financialRule.details) {
    scenarios.push({
      title: `Riesgo de fraude financiero`,
      desc: `La página contiene elementos diseñados para interceptar credenciales de acceso, contraseñas y números de tarjeta de crédito/débito.`,
      highlight: true
    });
  }

  if (geoRule?.triggered && geoRule.details) {
    scenarios.push({
      title: `Servidor en ${geoRule.details.country}`,
      desc: `El sitio opera desde ${geoRule.details.country} (${geoRule.details.country_code}), infraestructura comúnmente utilizada en campañas de distribución maliciosa.`
    });
  }

  const ageRule = allRules.find(r => r.rule === 'domain_age');
  if (ageRule?.triggered && ageRule.details) {
    scenarios.push({
      title: `Dominio de registro reciente (${ageRule.details.age_days} días)`,
      desc: `El dominio fue creado hace escasos días. La brevedad de existencia es un rasgo característico del phishing dinámico.`
    });
  }

  if (scenarios.length === 0) {
    scenarios.push({
      title: `Análisis de riesgo por IA`,
      desc: `El motor de detección identificó anomalías estructurales en "${hostname}". Se sugiere cautela absoluta.`
    });
  }

  return scenarios;
}

// Build accurate security recommendation
function buildRecommendation(prob, brand, allRules, brandMismatch, decisionType) {
  const bm = brandMismatch;
  const mismatchRule = allRules.find(r => r.rule === 'brand_country_mismatch');
  const brandMatch = bm || (mismatchRule?.triggered ? mismatchRule.details : null);
  const isDiff = bmDifferentEntity || brandMatch?.is_different_entity;

  if (decisionType === 'warning') {
    const name = brandMatch?.brand_full_name || bmName || 'tu entidad financiera';
    const localDom = brandMatch?.local_domain || bmDomain || 'el sitio oficial';

    if (isDiff) {
      return `No ingreses contraseñas, documentos de identidad ni información bancaria en este dominio foráneo. Si buscabas gestionar tus cuentas en ${name}, presiona el botón "Ir al sitio oficial" para navegar de forma protegida a ${localDom}.`;
    }
    return `Te recomendamos acceder directamente a la versión oficial correspondiente a tu país (${localDom}) para evitar bloqueos de sesión o problemas de autenticación regional.`;
  }

  if (prob >= 0.8) {
    return `ALERTA DE ALTO RIESGO: Este sitio ha sido clasificado como suplantación maliciosa de identidad. No ingreses datos personales, números de tarjeta ni claves de seguridad. Cierra esta pestaña inmediatamente.`;
  }

  return `Se detectaron patrones sospechosos consistentes con fraude digital. No proporciones credenciales de acceso y utiliza los canales oficiales verificados.`;
}

// Load and apply rules data
function loadRulesData(url) {
  if (typeof chrome === 'undefined' || !chrome.storage?.local) return;

  const storageKey = `rules_${url}`;
  const brandMismatchKey = `brand_mismatch_${url}`;

  chrome.storage.local.get([storageKey, brandMismatchKey]).then(data => {
    const rulesAnalysis = data[storageKey];
    const brandMismatch = data[brandMismatchKey];

    if (!rulesAnalysis?.all_rules) {
      setTimeout(() => {
        chrome.storage.local.get([storageKey, brandMismatchKey]).then(retryData => {
          if (retryData[storageKey]?.all_rules) {
            applyRulesData(retryData[storageKey], retryData[brandMismatchKey], url);
          }
        });
      }, 800);
      return;
    }

    applyRulesData(rulesAnalysis, brandMismatch, url);
  }).catch(() => {});
}

function applyRulesData(rulesAnalysis, brandMismatch, url) {
  const allRules = rulesAnalysis.all_rules || [];
  const geoEl = document.getElementById('geo-val');
  const ageEl = document.getElementById('age-val');

  // Geo origin
  const geoCtx = rulesAnalysis.geo_context;
  if (geoCtx && (geoCtx.origin_country || geoCtx.origin_country_name)) {
    const name = geoCtx.origin_country_name || geoCtx.origin_country;
    geoEl.textContent = `${name} (${geoCtx.origin_country})`;
    geoEl.className = geoCtx.is_foreign ? 'badge badge-warning' : 'badge badge-success';
  } else {
    for (const rule of allRules) {
      if (rule.rule === 'server_geolocation' && rule.details) {
        const d = rule.details;
        geoEl.textContent = `${d.country} (${d.country_code})`;
        geoEl.className = rule.triggered ? 'badge badge-danger' : 'badge badge-neutral';
        break;
      }
    }
  }

  // Domain age
  for (const rule of allRules) {
    if (rule.rule === 'domain_age') {
      if (ageEl) {
        if (rule.details?.age_days !== undefined) {
          ageEl.textContent = `${rule.details.age_days} días`;
          ageEl.className = rule.triggered ? 'badge badge-danger' : 'badge badge-neutral';
        } else {
          ageEl.textContent = 'No disponible';
          ageEl.className = 'badge badge-neutral';
        }
      }
      break;
    }
  }

  // Dynamic texts
  const brand = extractBrandFromUrl(url);
  const purposeEl = document.getElementById('page-purpose-text');
  const recEl = document.getElementById('rec-value');
  const gridEl = document.getElementById('scenarios-grid');

  if (purposeEl) purposeEl.textContent = buildPurpose(url, brand, allRules, brandMismatch, decisionType);
  if (recEl) recEl.textContent = buildRecommendation(parseFloat(probability || 0), brand, allRules, brandMismatch, decisionType);

  const scenarios = buildScenarios(url, brand, allRules, brandMismatch, decisionType);
  if (gridEl && scenarios.length > 0) {
    gridEl.innerHTML = scenarios.map((s, i) => `
      <div class="scenario-item" ${s.highlight ? 'style="border-color: rgba(56, 189, 248, 0.4); background: rgba(14, 165, 233, 0.08);"' : ''}>
        <div class="scenario-badge" ${s.highlight ? 'style="background: rgba(2, 132, 199, 0.25); color: #38bdf8; border-color: rgba(56, 189, 248, 0.4);"' : ''}>0${i + 1}</div>
        <div class="scenario-content">
          <span class="scenario-title">${s.title}</span>
          <p class="scenario-desc">${s.desc}</p>
        </div>
      </div>
    `).join('');
  }

  chrome.storage.local.remove(`rules_${url}`);
}
