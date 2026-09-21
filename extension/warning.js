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
const hasBmData = !!(bmName && bmDomain);

// PENDING MODE: backend is still processing, show spinner and poll
if (isPending && targetUrl) {
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelector('.warning-banner').style.background = 'linear-gradient(135deg, #eff6ff, #dbeafe)';
    document.querySelector('.warning-banner').style.borderColor = '#3b82f6';
    document.querySelector('.warning-icon-wrap').style.background = '#3b82f6';
    document.querySelector('.warning-icon-wrap').innerHTML = '<div class="spinner"></div>';
    document.getElementById('main-title').textContent = 'Analizando sitio...';
    document.getElementById('main-desc').textContent = 'PhishGuard está verificando la seguridad de este dominio. Esto puede tomar unos segundos.';
    document.querySelector('.url-status-badge').textContent = '⏳ Analizando';
    document.querySelector('.url-status-badge').style.background = '#dbeafe';
    document.querySelector('.url-status-badge').style.color = '#1d4ed8';
    document.querySelector('.page-subtitle').textContent = 'Verificación en curso contra el motor de detección.';
    document.getElementById('btn-close').style.display = 'none';
    document.getElementById('btn-ignore').style.display = 'none';
    document.getElementById('url-display').textContent = targetUrl;

    // Hide non-essential sections while loading
    document.getElementById('scenarios-card').style.display = 'none';
    document.querySelector('.rec-banner').style.display = 'none';
    const previewCard = document.getElementById('preview-container')?.closest('.card');
    if (previewCard) previewCard.style.display = 'none';

    // Poll for result
    const resultKey = `result_${targetUrl}`;
    const rulesKey = `rules_${targetUrl}`;
    const bmKey = `brand_mismatch_${targetUrl}`;
    let attempts = 0;
    const poll = setInterval(async () => {
      attempts++;
      if (attempts > 60) { clearInterval(poll); return; } // 30s max
      try {
        const data = await chrome.storage.local.get([resultKey, rulesKey, bmKey]);
        const result = data[resultKey];
        if (result?.ready) {
          clearInterval(poll);
          // Rewrite URL params and reload in normal mode
          const newParams = new URLSearchParams({
            url: targetUrl,
            probability: result.probability,
            decision: result.decision
          });
          // Pass brand_mismatch data directly via URL to avoid storage race
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

// === NORMAL MODE (not pending) ===
if (!isPending) {
if (decisionType === 'legitimate') {
  document.querySelector('.warning-banner').style.background = 'linear-gradient(135deg, #f0fdf4, #bbf7d0)';
  document.querySelector('.warning-banner').style.borderColor = '#16a34a';
  document.querySelector('.warning-icon-wrap').style.background = '#16a34a';
  document.querySelector('.warning-icon-wrap').textContent = '✓';
  document.getElementById('main-title').textContent = 'Sitio seguro';
  document.getElementById('main-desc').textContent = 'Este sitio no presenta indicaciones de phishing. Puedes navegar con normalidad.';
  document.querySelector('.url-status-badge').textContent = '✓ Seguro';
  document.querySelector('.url-status-badge').style.background = '#f0fdf4';
  document.querySelector('.url-status-badge').style.color = '#166534';
  document.querySelector('.page-subtitle').textContent = 'El análisis determinó que este sitio es seguro.';
  document.getElementById('btn-close').innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
    Ir al sitio
  `;
  document.getElementById('btn-close').className = 'btn';
  document.getElementById('btn-close').style.background = '#16a34a';
  document.getElementById('btn-close').style.color = 'white';
  document.getElementById('btn-ignore').textContent = 'Volver atrás';
} else if (decisionType === 'warning') {
  document.querySelector('.warning-banner').style.background = 'linear-gradient(135deg, #fef3c7, #fde68a)';
  document.querySelector('.warning-banner').style.borderColor = '#f59e0b';
  document.querySelector('.warning-icon-wrap').style.background = '#f59e0b';
  document.querySelector('.warning-icon-wrap').textContent = '⚠';
  document.getElementById('main-title').textContent = 'Advertencia: Dominio fuera de tu región';
  document.getElementById('main-desc').textContent = 'Este sitio pertenece a una marca conocida pero no es la versión para tu país. Puede ser legítimo, pero verifica que sea la versión correcta.';
  document.querySelector('.url-status-badge').textContent = '⚠ Advertencia';
  document.querySelector('.url-status-badge').style.background = '#fef3c7';
  document.querySelector('.url-status-badge').style.color = '#92400e';
  document.querySelector('.page-subtitle').textContent = 'Análisis geográfico de dominio detectó una inconsistencia de ubicación.';

  // Adapt sections for warning mode
  document.querySelector('#scenarios-card h3').textContent = '📋 Información del Sitio y Contexto Geográfico';
  document.querySelector('#scenarios-card .badge').textContent = 'Contexto Regional';
  document.querySelector('#scenarios-card .badge').className = 'badge badge-warning';
  document.querySelector('#scenarios-card .badge').style.fontSize = '11px';
  document.querySelector('#scenarios-card .badge').style.background = '#fef3c7';
  document.querySelector('#scenarios-card .badge').style.color = '#92400e';

  // Change "¿Qué ocurriría..." subtitle
  const scenariosSubtitle = document.querySelector('#scenarios-card [style*="font-size: 13px; font-weight: 700"]');
  if (scenariosSubtitle) scenariosSubtitle.textContent = '📍 Detalles del análisis geográfico:';

  // Change button labels
  document.getElementById('btn-close').innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
    Ir a la versión de mi país
  `;
  document.getElementById('btn-close').className = 'btn';
  document.getElementById('btn-close').style.background = '#2563eb';
  document.getElementById('btn-close').style.color = 'white';
  document.getElementById('btn-ignore').textContent = 'Continuar en este sitio de todos modos';

  // Change why-percentage-steps for warning
  const whyBlock = document.querySelector('.why-block');
  if (whyBlock) {
    const steps = whyBlock.querySelectorAll('.why-step');
    if (steps[0]) steps[0].querySelector('div').innerHTML = '<b>Análisis de marca:</b> Se verificó si el dominio pertenece a una institución financiera reconocida.';
    if (steps[1]) steps[1].querySelector('div').innerHTML = '<b>Geolocalización del usuario:</b> Se comparó tu ubicación con la región del dominio visitado.';
    if (steps[2]) steps[2].querySelector('div').innerHTML = '<b>Decisión:</b> El dominio es legítimo pero no corresponde a la versión de tu país.';
  }
}

// Populate URL info
if (targetUrl) {
  document.getElementById('url-display').textContent = targetUrl;
  try {
    const u = new URL(targetUrl);
    document.getElementById('domain-val').textContent = u.hostname;
    const isHttps = u.protocol === 'https:';
    const sslEl = document.getElementById('ssl-val');
    sslEl.textContent = isHttps ? 'HTTPS Cifrado' : 'HTTP No Seguro';
    sslEl.className = isHttps ? 'badge badge-warning' : 'badge badge-danger';
  } catch (e) {
    document.getElementById('domain-val').textContent = targetUrl;
  }

  // Load geolocation and domain age from rules_analysis
  loadRulesData(targetUrl);
}

// Close tab button / Navigate to local version
document.getElementById('btn-close').addEventListener('click', () => {
  if (decisionType === 'warning') {
    // In warning mode, load rules to find the local_domain and navigate there
    const storageKey = `rules_${targetUrl}`;
    const brandMismatchKey = `brand_mismatch_${targetUrl}`;
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get([storageKey, brandMismatchKey]).then((data) => {
        const bm = data[brandMismatchKey];
        const rulesAnalysis = data[storageKey];
        const mismatchRule = rulesAnalysis?.all_rules?.find(r => r.rule === 'brand_country_mismatch');
        const brandMatch = bm || (mismatchRule?.triggered ? mismatchRule.details : null);
        if (brandMatch?.local_domain) {
          const localUrl = brandMatch.local_domain.startsWith('http') ? brandMatch.local_domain : `https://${brandMatch.local_domain}`;
          window.location.href = localUrl;
        } else {
          window.close();
        }
      }).catch(() => window.close());
    } else {
      window.close();
    }
    return;
  }
  if (decisionType === 'legitimate') {
    // Navigate to the legitimate URL
    if (targetUrl) {
      window.location.href = targetUrl;
    }
    return;
  }
  try {
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.getCurrent) {
      chrome.tabs.getCurrent(tab => {
        if (tab && tab.id) {
          chrome.tabs.remove(tab.id);
        } else {
          window.close();
        }
      });
    } else {
      window.close();
    }
  } catch (e) {
    window.close();
  }
});

// Ignore button
document.getElementById('btn-ignore').addEventListener('click', () => {
  const finalUrl = targetUrl || document.getElementById('url-display').textContent;
  if (finalUrl && !finalUrl.startsWith('Cargando')) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get({ allowed_urls: [] }).then(({ allowed_urls }) => {
        const allowed = allowed_urls || [];
        try {
          const origin = new URL(finalUrl).origin;
          const existing = allowed.find(e => e.origin === origin);
          if (!existing) {
            allowed.push({ origin, timestamp: Date.now() });
          }
        } catch (e) {
          const existing = allowed.find(e => e.origin === finalUrl);
          if (!existing) {
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
  }
});

// Detect brand with fuzzy matching
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({length: m + 1}, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[m][n];
}

function extractBrandFromUrl(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, '');
    const domain = hostname.split('.')[0];
    const brands = ['facebook','google','microsoft','apple','amazon','paypal','netflix','instagram','whatsapp','twitter','linkedin','github','bbva','bcp','banco','santander','hsbc','scotiabank','interbank','bancoazteca','banrural','bancamiga','bancochile','itau','bradesco','bancocontinental','mibanco','pichincha','bancolombia','davivienda','bankaool','nu','rappi','mercadopago'];
    
    let bestBrand = null, bestDist = Infinity;
    for (const brand of brands) {
      const dist = levenshtein(domain, brand);
      if (dist <= 2 && dist < bestDist) {
        bestDist = dist;
        bestBrand = brand;
      }
    }
    if (bestBrand) return bestBrand.charAt(0).toUpperCase() + bestBrand.slice(1);
  } catch (e) {}
  return null;
}

// Main logic: use jobId or direct probability
function populateWithCheckData(prob, url) {
  const probPct = (prob * 100).toFixed(1) + '%';
  const isWarning = decisionType === 'warning';
  
  document.getElementById('prob-val').textContent = probPct;
  document.getElementById('risk-pct-banner').textContent = probPct;

  const riskEl = document.getElementById('risk-text');
  if (isWarning) {
    riskEl.textContent = 'PRECAUCIÓN';
    riskEl.style.color = '#d97706';
  } else if (prob >= 0.8) {
    riskEl.textContent = 'CRÍTICO';
    riskEl.style.color = '#dc2626';
  } else if (prob >= 0.5) {
    riskEl.textContent = 'MEDIO';
    riskEl.style.color = '#d97706';
  } else {
    riskEl.textContent = 'BAJO';
    riskEl.style.color = '#16a34a';
  }

  // Detect brand
  const brand = extractBrandFromUrl(url);
  const hostname = (() => { try { return new URL(url).hostname; } catch(e) { return url; } })();

  if (isWarning) {
    document.getElementById('brand-val').textContent = brand || 'Marca reconocida';
    document.getElementById('brand-val').className = 'badge badge-warning';
    document.getElementById('threat-val').textContent = 'Dominio legítimo fuera de región';
    document.getElementById('threat-val').className = 'badge badge-warning';
    document.getElementById('main-title').textContent = 'Advertencia: Dominio fuera de tu región';
    document.getElementById('main-desc').textContent = 'Este sitio pertenece a una marca conocida pero no es la versión para tu país. Puede ser legítimo, pero verifica que sea la versión correcta.';
  } else {
    if (brand) {
      document.getElementById('brand-val').textContent = brand;
      document.getElementById('threat-val').textContent = `Suplantación de ${brand} (Typosquatting)`;
      document.getElementById('main-title').textContent = `Peligro: Suplantación de ${brand}`;
      document.getElementById('main-desc').innerHTML = `<b>Diagnóstico de IA:</b> El dominio parece ser una suplantación de ${brand}. Se recomienda no interactuar ni ingresar contraseñas.`;
    } else {
      document.getElementById('brand-val').textContent = 'Dominio de riesgo genérico';
      document.getElementById('threat-val').textContent = 'Sitio sospechoso de phishing';
    }
  }

  // Why description
  if (isWarning) {
    document.getElementById('why-percentage-desc').textContent =
      `Este dominio fue identificado como una marca conocida. El análisis geográfico detectó que no corresponde a la versión de tu país.`;
  } else {
    const geoEl = document.getElementById('geo-val');
    const geoText = geoEl && geoEl.textContent !== 'Verificando...' ? geoEl.textContent : '';
    const geoWarning = geoText ? ` El servidor está ubicado en ${geoText}, una región con alta asociación a campañas de phishing.` : '';
    document.getElementById('why-percentage-desc').textContent =
      `Se asignó un score de riesgo del ${probPct}. El modelo M0+Brand+Rules detectó patrones sospechosos en la estructura del dominio.${geoWarning} ${brand ? `La marca "${brand}" podría estar siendo suplantada.` : ''}`;
  }

  // Recommendation
  if (isWarning) {
    const recBrand = hasBmData ? bmName : brand;
    const recDomain = hasBmData ? bmDomain : '';
    if (recBrand && recDomain) {
      document.getElementById('rec-value').textContent = bmDifferentEntity
        ? `Este sitio es seguro pero es de otro país. Si buscas ${recBrand} de tu país, te recomendamos visitar ${recDomain}.`
        : `Si buscas ${recBrand}, te recomendamos visitar ${recDomain} directamente. Estás en la versión de ${recBrand} para otro país, no para el tuyo.`;
    } else if (recBrand) {
      document.getElementById('rec-value').textContent = `Si buscas ${recBrand}, te recomendamos acceder a la versión oficial de tu país. Busca "${recBrand}" en tu buscador o utiliza la app oficial.`;
    } else {
      document.getElementById('rec-value').textContent = 'Verifica que este sitio corresponda a la versión correcta para tu país antes de ingresar datos.';
    }
  } else {
    document.getElementById('rec-value').textContent = 'Cierra esta página inmediatamente. No ingreses credenciales ni datos personales en este sitio.';
  }

  // Purpose text
  if (isWarning && hasBmData) {
    document.getElementById('page-purpose-text').textContent = bmDifferentEntity
      ? `Este sitio coincide con la marca ${bmName} pero es de otro país. Estás visitando ${hostname} y la versión local es ${bmDomain}.`
      : `Este sitio pertenece a ${bmName} (${bmCategory || 'institución financiera'}) pero no es la versión de tu país. Estás visitando ${hostname} y la versión local es ${bmDomain}.`;
  } else if (isWarning) {
    document.getElementById('page-purpose-text').textContent = brand
      ? `Portal de ${brand}. Dominio: ${hostname}. Este es un sitio legítimo, pero no es la versión para tu país.`
      : `Sitio clasificado como sospechoso por análisis multiminal. Dominio: ${hostname}.`;
  } else {
    document.getElementById('page-purpose-text').textContent = brand
      ? `Portal sospechoso que suplanta la marca "${brand}". Dominio: ${hostname}. El modelo de IA detectó un ${(prob * 100).toFixed(0)}% de riesgo en este sitio.`
      : `Sitio sospechoso detectado por análisis multiminal. Dominio: ${hostname}.`;
  }

  // Scenario cards
  const scenariosGrid = document.getElementById('scenarios-grid');
  if (scenariosGrid) {
    const scenarios = [];
    if (isWarning && hasBmData) {
      if (bmDifferentEntity) {
        scenarios.push({
          title: `${bmName} — Distinto país`,
          desc: `Este sitio (${hostname}) es seguro pero es de otro país. Si buscas ${bmName} de tu país, visita ${bmDomain}.`,
          highlight: true
        });
      } else {
        scenarios.push({
          title: `${bmName} — Fuera de tu región`,
          desc: `Estás visitando ${hostname}, que es la versión de ${bmName} para otro país. La versión de tu país es ${bmDomain}. ${bmSuggestion || ''}`,
          highlight: true
        });
      }
    } else if (isWarning && brand) {
      scenarios.push({
        title: `${brand} — Fuera de región`,
        desc: `Estás visitando la versión de ${brand} para otro país. Verifica que sea la versión correcta para tu ubicación.`,
        highlight: true
      });
    } else if (brand) {
      scenarios.push({
        title: `Suplantación de ${brand}`,
        desc: `El dominio imita la marca "${brand}" mediante typosquatting. Los usuarios podrían confundirlo con el sitio legítimo y ingresar credenciales.`
      });
    } else {
      scenarios.push({
        title: 'Análisis de riesgo por IA',
        desc: `El modelo multiminal detectó patrones anómalos en "${hostname}" con un score de riesgo del ${(prob * 100).toFixed(0)}%.`
      });
    }
    scenariosGrid.innerHTML = scenarios.map((s, i) => `
      <div class="scenario-item" ${s.highlight ? 'style="background:#eff6ff;border-color:#93c5fd;"' : ''}>
        <div class="scenario-badge" ${s.highlight ? 'style="background:#dbeafe;color:#2563eb;"' : ''}>${i + 1}</div>
        <div class="scenario-content">
          <span class="scenario-title">${s.title}</span>
          <p class="scenario-desc">${s.desc}</p>
        </div>
      </div>
    `).join('');
  }

  // Load screenshot preview for ALL scenarios (phishing, warning, legitimate)
  {
    const ANALYSES_ENDPOINT = 'http://localhost:8080/analyses';
    const previewContainer = document.getElementById('preview-container');
    
    previewContainer.innerHTML = `
      <div style="font-size: 30px; margin-bottom: 8px;">⏳</div>
      <div class="preview-box-title" style="color: #334155; font-size: 15px;">Generando Captura Segura...</div>
      <div class="preview-box-desc" style="color: #64748b; font-size: 13px;">
        El servidor está capturando el sitio en un entorno aislado.
      </div>
    `;

    fetch(ANALYSES_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    })
    .then(res => res.json())
    .then(job => {
      const pollInterval = setInterval(async () => {
        try {
          const response = await fetch(`${ANALYSES_ENDPOINT}/${job.id}`);
          const data = await response.json();
          
          if (data.status === 'completed' || data.status === 'failed') {
            clearInterval(pollInterval);
            
            if (data.status === 'completed') {
              const screenshotUrl = `${ANALYSES_ENDPOINT.replace('/analyses', '')}/screenshots/${job.id}.png`;
              previewContainer.className = '';
              previewContainer.style.padding = '0';
            previewContainer.style.border = '1px solid #cbd5e1';
            previewContainer.style.borderRadius = '10px';
            previewContainer.style.overflow = 'hidden';
            previewContainer.style.background = '#ffffff';
            previewContainer.innerHTML = `
              <div style="background: #0f172a; color: #94a3b8; font-size: 12px; padding: 10px 16px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155;">
                <div style="background: #1e293b; padding: 3px 14px; border-radius: 6px; font-family: monospace; color: #e2e8f0; font-size: 11.5px; border: 1px solid #334155;">
                  🔒 ${url}
                </div>
                <span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); font-size: 11px;">Captura Inerte</span>
              </div>
              <div style="max-height: 500px; overflow-y: auto; background: #f8fafc; text-align: center;">
                <img id="screenshot-img" src="${screenshotUrl}" alt="Captura del sitio" style="width: 100%; height: auto; display: block;">
              </div>
              <div style="background: #f8fafc; padding: 10px 16px; font-size: 12px; color: #475569;">
                🛡️ <b>Entorno Aislado:</b> Imagen estática generada por Playwright. Sin scripts activos.
              </div>
            `;
            const img = document.getElementById('screenshot-img');
            if (img) {
              img.addEventListener('error', () => {
                img.parentElement.innerHTML = '<div style="padding:40px;color:#64748b">No se pudo cargar la captura</div>';
              });
            }
          } else {
            previewContainer.className = 'preview-box';
            previewContainer.innerHTML = `
              <div style="font-size: 34px; margin-bottom: 10px;">🌐⚠️</div>
              <div class="preview-box-title" style="color: #334155;">Sitio Inactivo o Fuera de Línea</div>
              <div class="preview-box-desc" style="color: #64748b;">No se pudo capturar. El dominio puede estar caído o sin DNS.</div>
            `;
          }
        }
      } catch (e) {
        clearInterval(pollInterval);
      }
    }, 2000);

    setTimeout(() => {
      clearInterval(pollInterval);
      if (previewContainer.querySelector('.preview-box-title')?.textContent.includes('Generando')) {
        previewContainer.className = 'preview-box';
        previewContainer.innerHTML = `
          <div style="font-size: 34px; margin-bottom: 10px;">🌐⚠️</div>
          <div class="preview-box-title" style="color: #334155;">Tiempo de espera agotado</div>
          <div class="preview-box-desc" style="color: #64748b;">El sitio puede estar inactivo o sin resolución DNS.</div>
        `;
      }
    }, 30000);
  })
  .catch(err => {
    console.error('Error:', err);
    previewContainer.className = 'preview-box';
    previewContainer.innerHTML = `
      <div style="font-size: 34px; margin-bottom: 10px;">📷</div>
      <div class="preview-box-title" style="color: #334155;">Vista previa no disponible</div>
      <div class="preview-box-desc" style="color: #64748b;">No se pudo conectar con el servidor.</div>
    `;
  });
}
}

// Build dynamic attack scenarios from rules
function buildScenarios(url, brand, allRules, brandMismatch, decisionType) {
  const scenarios = [];

  const bm = brandMismatch;
  const mismatchRule = allRules.find(r => r.rule === 'brand_country_mismatch');
  const brandMatch = bm || (mismatchRule?.triggered ? mismatchRule.details : null);

  if (decisionType === 'warning' && brandMatch) {
    if (bmDifferentEntity) {
      scenarios.push({
        title: `${brandMatch.brand_full_name} — Distinto país`,
        desc: `Este sitio (${brandMatch.current_domain || url}) es seguro pero es de otro país. Si buscas ${brandMatch.brand_full_name} de tu país, visita ${brandMatch.local_domain}.`,
        highlight: true
      });
    } else {
      scenarios.push({
        title: `${brandMatch.brand_full_name} — Fuera de tu región`,
        desc: `Estás visitando ${brandMatch.current_domain || 'este dominio'}, que es la versión de ${brandMatch.brand_full_name} para otro país. La versión de tu país es ${brandMatch.local_domain}.`,
        highlight: true
      });
    }
  } else if (brandMatch) {
    scenarios.push({
      title: `${brandMatch.brand_full_name} — Versión incorrecta`,
      desc: `Estás visitando ${brandMatch.current_domain || 'este dominio'}, pero la versión local para tu país es ${brandMatch.local_domain}. ${brandMatch.suggestion || ''}.`,
      highlight: true
    });
  }

  if (brand && !brandMatch) {
    scenarios.push({
      title: `Suplantación de ${brand}`,
      desc: `El dominio imita la marca "${brand}" mediante typosquatting. Los usuarios podrían confundirlo con el sitio legítimo y ingresar credenciales.`
    });
  }

  // Financial phishing scenario
  const financialRule = allRules.find(r => r.rule === 'financial_phishing');
  if (financialRule?.triggered && financialRule.details) {
    const d = financialRule.details;
    if (d.type === 'brand_impersonation') {
      scenarios.push({
        title: `Phishing financiero: ${d.brand || 'institución'}`,
        desc: `Se detectó suplantación de ${d.brand || 'una institución financiera'} (${d.category || 'banco'}). Este tipo de ataque busca robar credenciales bancarias, datos de tarjetas y documentos de identidad.`,
        highlight: true
      });
    } else if (d.type === 'keyword_pattern') {
      scenarios.push({
        title: 'Patrón de phishing financiero detectado',
        desc: `La URL contiene ${d.keywords?.length || 0} términos financieros sospechosos (${(d.keywords || []).slice(0, 4).join(', ')}). Sitios legítimos de bancos no usan estas rutas en URLs públicas.`
      });
    }
  }

  const geoRule = allRules.find(r => r.rule === 'server_geolocation');
  if (geoRule?.triggered && geoRule.details) {
    scenarios.push({
      title: `Servidor en ${geoRule.details.country}`,
      desc: `El sitio opera desde ${geoRule.details.country} (${geoRule.details.country_code}), una región con alta prevalencia de campañas de phishing. ISP: ${geoRule.details.isp || 'desconocido'}.`
    });
  }

  const ageRule = allRules.find(r => r.rule === 'domain_age');
  if (ageRule?.triggered && ageRule.details) {
    scenarios.push({
      title: `Dominio recién registrado (${ageRule.details.age_days} días)`,
      desc: `El dominio fue registrado hace apenas ${ageRule.details.age_days} días. Los dominios nuevos son frecuentemente utilizados en campañas de phishing activas.`
    });
  }

  const tldRule = allRules.find(r => r.rule === 'suspicious_tld' || r.rule === 'country_code_tld');
  if (tldRule?.triggered && tldRule.details) {
    scenarios.push({
      title: `TLD de riesgo: .${tldRule.details.tld}`,
      desc: `El dominio utiliza .${tldRule.details.tld}, un TLD frecuentemente abusado por su bajo costo y mínima verificación de registro.`
    });
  }

  const pathRule = allRules.find(r => r.rule === 'suspicious_path');
  if (pathRule?.triggered && pathRule.details) {
    const kws = pathRule.details.keywords?.join(', ') || '';
    scenarios.push({
      title: 'Ruta sospechosa detectada',
      desc: `La URL contiene términos asociados a robo de credenciales: ${kws}. Estas rutas simulan páginas de login legítimas.`
    });
  }

  const ipRule = allRules.find(r => r.rule === 'ip_address');
  if (ipRule?.triggered) {
    scenarios.push({
      title: 'IP directa en lugar de dominio',
      desc: 'El sitio usa una dirección IP numérica en lugar de un nombre de dominio, técnica común para evadir bloqueos y filtros.'
    });
  }

  const shortenerRule = allRules.find(r => r.rule === 'url_shortener');
  if (shortenerRule?.triggered) {
    scenarios.push({
      title: 'Acortador de URLs detectado',
      desc: 'Se utilizó un servicio de acortamiento de URLs para ocultar el destino real, una técnica habitual en campañas de phishing.'
    });
  }

  if (scenarios.length === 0) {
    const riskPct = (parseFloat(probability) * 100).toFixed(0);
    const hostname = (() => { try { return new URL(url).hostname; } catch(e) { return url; } })();
    const mismatchRule = allRules.find(r => r.rule === 'brand_country_mismatch');

    if (mismatchRule?.details) {
      const d = mismatchRule.details;
      scenarios.push({
        title: `${d.brand_full_name} — Análisis de riesgo`,
        desc: `El modelo de IA detectó un ${riskPct}% de riesgo en "${hostname}". Este dominio fue analizado por sus patrones de similitud con ${d.brand_full_name} (${d.category || 'institución financiera'}). Servidor en ${d.server_country_name || 'ubicación no determinada'}.`,
        highlight: true
      });
    } else {
      scenarios.push({
        title: 'Análisis de riesgo por IA',
        desc: `El modelo multiminal detectó patrones anómalos en "${hostname}" con un score de riesgo del ${riskPct}%. Se analizó la estructura del dominio, la geolocalización del servidor y la edad del dominio.`
      });
    }

    if (geoRule?.details?.country) {
      scenarios.push({
        title: `Servidor en ${geoRule.details.country}`,
        desc: `El dominio ${hostname} resuelve a un servidor ubicado en ${geoRule.details.country} (${geoRule.details.country_code || ''}). ISP: ${geoRule.details.isp || 'desconocido'}.`
      });
    }
  }

  return scenarios;
}

// Build dynamic purpose text
function buildPurpose(url, brand, allRules, brandMismatch, decisionType) {
  const triggeredNames = allRules.filter(r => r.triggered).map(r => r.rule);
  const hostname = (() => { try { return new URL(url).hostname; } catch(e) { return url; } })();
  const prob = parseFloat(probability);
  const riskPct = (prob * 100).toFixed(0);

  const bm = brandMismatch;
  const mismatchRule = allRules.find(r => r.rule === 'brand_country_mismatch');
  const brandMatch = bm || (mismatchRule?.triggered ? mismatchRule.details : null);

  if (decisionType === 'warning' && brandMatch) {
    return bmDifferentEntity
      ? `Este sitio coincide con la marca ${brandMatch.brand_full_name} pero es de otro país. Estás visitando ${hostname} y la versión local es ${brandMatch.local_domain}.`
      : `Este sitio pertenece a ${brandMatch.brand_full_name} (${brandMatch.category || 'institución financiera'}) pero no es la versión de tu país. Estás visitando ${hostname} y la versión local es ${brandMatch.local_domain}.`;
  }

  if (brandMatch) {
    return `Estás visitando ${hostname}, que pertenece a ${brandMatch.brand_full_name} (${brandMatch.category || 'institución'}). La versión de tu país es ${brandMatch.local_domain}. El modelo de IA asignó un ${riskPct}% de riesgo.`;
  }

  if (brand) {
    return `Portal sospechoso que suplanta la marca "${brand}". Dominio: ${hostname}. El modelo de IA detectó un ${riskPct}% de riesgo en este sitio.`;
  }

  // Generic but informative
  const geoRule = allRules.find(r => r.rule === 'server_geolocation');
  const ageRule = allRules.find(r => r.rule === 'domain_age');

  let text = `Sitio clasificado como sospechoso por análisis multiminal. Dominio: ${hostname}. `;
  text += `El modelo de IA asignó un ${riskPct}% de probabilidad de ser phishing.`;

  if (geoRule?.details?.country) {
    text += ` Servidor ubicado en ${geoRule.details.country}.`;
  }
  if (ageRule?.details?.age_days) {
    text += ` Dominio registrado hace ${ageRule.details.age_days} días.`;
  }
  if (triggeredNames.length > 0) {
    text += ` Reglas activadas: ${triggeredNames.join(', ')}.`;
  }
  return text;
}

// Build dynamic recommendation
function buildRecommendation(prob, brand, allRules, brandMismatch, decisionType) {
  const parts = [];
  const riskPct = (prob * 100).toFixed(0);

  const bm = brandMismatch;
  const mismatchRule = allRules.find(r => r.rule === 'brand_country_mismatch');
  // Only use brand info if API sent brand_mismatch (rule triggered) or rule is triggered
  const brandMatch = bm || (mismatchRule?.triggered ? mismatchRule.details : null);

  if (decisionType === 'warning' && brandMatch) {
    if (bmDifferentEntity) {
      parts.push(`Este sitio es seguro pero es de otro país. Si buscas ${brandMatch.brand_full_name} de tu país, te recomendamos visitar ${brandMatch.local_domain}.`);
    } else {
      parts.push(`Si buscas ${brandMatch.brand_full_name}, te recomendamos visitar ${brandMatch.local_domain} directamente.`);
      parts.push(`Estás en la versión de ${brandMatch.brand_full_name} para otro país, no para el tuyo.`);
    }
    return parts.join(' ');
  }

  // Brand-country mismatch suggestion
  if (brandMatch) {
    if (brandMatch.local_domain) {
      parts.push(`Si buscas ${brandMatch.brand_full_name}, te recomendamos visitar ${brandMatch.local_domain} directamente.`);
    }
    parts.push(`Estás visitando ${brandMatch.current_domain || 'un dominio diferente'}, pero la versión de tu país es ${brandMatch.local_domain}.`);
  }

  // Financial-specific warning
  const financialRule = allRules.find(r => r.rule === 'financial_phishing');
  if (financialRule?.triggered && financialRule.details) {
    const d = financialRule.details;
    if (d.type === 'brand_impersonation') {
      parts.push(`ATENCIÓN: Este sitio suplanta una institución financiera (${d.brand || 'banco'}). Nunca ingreses credenciales bancarias.`);
    } else {
      parts.push(`La URL contiene términos financieros sospechosos. No ingresas datos bancarios.`);
    }
  }

  // Context-specific recommendations based on risk level
  if (prob >= 0.8) {
    parts.push(`Este sitio tiene un riesgo MUY ALTO (${riskPct}%). No ingreses ningún dato personal ni financiero.`);
  } else if (prob >= 0.6) {
    parts.push(`Este sitio tiene un riesgo alto (${riskPct}%). Evita ingresar credenciales o datos sensibles.`);
  } else {
    parts.push(`Este sitio tiene un riesgo moderado (${riskPct}%). No ingreses credenciales ni datos personales.`);
  }

  parts.push('Si necesitas acceder a este servicio, busca el sitio oficial en tu buscador o utiliza la app oficial.');
  return parts.join(' ');
}

// Load geolocation, domain age, scenarios, purpose, recommendation from rules_analysis
function loadRulesData(url) {
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;

  const storageKey = `rules_${url}`;
  const brandMismatchKey = `brand_mismatch_${url}`;
  chrome.storage.local.get([storageKey, brandMismatchKey]).then((data) => {
    const rulesAnalysis = data[storageKey];
    const brandMismatch = data[brandMismatchKey];
    
    if (!rulesAnalysis || !rulesAnalysis.all_rules) {
      // Retry once after 1 second (data might not have been written yet)
      setTimeout(() => {
        chrome.storage.local.get([storageKey, brandMismatchKey]).then((retryData) => {
          const retryRules = retryData[storageKey];
          const retryBm = retryData[brandMismatchKey];
          if (retryRules && retryRules.all_rules) {
            applyRulesData(retryRules, retryBm, url);
          }
        });
      }, 1000);
      return;
    }

    applyRulesData(rulesAnalysis, brandMismatch, url);
  }).catch(() => {});
}

function applyRulesData(rulesAnalysis, brandMismatch, url) {
    const allRules = rulesAnalysis.all_rules;
    const geoEl = document.getElementById('geo-val');
    const ageEl = document.getElementById('age-val');

    for (const rule of allRules) {
      if (rule.rule === 'server_geolocation' && rule.details) {
        const d = rule.details;
        if (rule.triggered) {
          geoEl.textContent = `${d.country} (${d.country_code})`;
          geoEl.className = d.risk_level === 'high' ? 'badge badge-danger' : 'badge badge-warning';
        } else if (d.country) {
          geoEl.textContent = `${d.country} (${d.country_code})`;
          geoEl.className = 'badge badge-neutral';
        }
      }

      if (rule.rule === 'domain_age') {
        if (ageEl) {
          if (rule.details && rule.details.age_days) {
            ageEl.textContent = `${rule.details.age_days} días`;
            ageEl.className = rule.triggered
              ? (rule.details.risk_level === 'critical' || rule.details.risk_level === 'high' ? 'badge badge-danger' : 'badge badge-warning')
              : 'badge badge-neutral';
          } else {
            ageEl.textContent = 'No disponible';
            ageEl.className = 'badge badge-neutral';
          }
        }
      }
    }

    // Update dynamic sections
    const brand = extractBrandFromUrl(url);

    const purposeEl = document.getElementById('page-purpose-text');
    const recEl = document.getElementById('rec-value');
    const gridEl = document.getElementById('scenarios-grid');

    if (purposeEl) purposeEl.textContent = buildPurpose(url, brand, allRules, brandMismatch, decisionType);
    if (recEl) recEl.textContent = buildRecommendation(parseFloat(probability), brand, allRules, brandMismatch, decisionType);

    const scenarios = buildScenarios(url, brand, allRules, brandMismatch, decisionType);
    if (gridEl && scenarios.length > 0) {
      gridEl.innerHTML = scenarios.map((s, i) => `
        <div class="scenario-item" ${s.highlight ? 'style="background:#eff6ff;border-color:#93c5fd;"' : ''}>
          <div class="scenario-badge" ${s.highlight ? 'style="background:#dbeafe;color:#2563eb;"' : ''}>${i + 1}</div>
          <div class="scenario-content">
            <span class="scenario-title">${s.title}</span>
            <p class="scenario-desc">${s.desc}</p>
          </div>
        </div>
      `).join('');
    }

    // Clean up stored data
    chrome.storage.local.remove(`rules_${url}`);
}

// Main logic: use jobId or direct probability
if (probability) {
  // Direct from /check endpoint
  populateWithCheckData(parseFloat(probability), targetUrl);
} else if (jobId) {
  // Legacy: fetch from /analyses endpoint
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
          sslEl.className = isHttps ? 'badge badge-warning' : 'badge badge-danger';
        } catch (e) {
          document.getElementById('domain-val').textContent = data.url;
        }
      }

      const prob = Number(data.probability ?? 1.0);
      populateWithCheckData(prob, data.url || targetUrl);
    })
    .catch(err => {
      console.error('Error loading job details:', err);
      // Fallback: show with high risk
      populateWithCheckData(1.0, targetUrl);
    });
} else {
  // No probability or jobId: default to high risk
  populateWithCheckData(1.0, targetUrl);
}
} // end if (!isPending)
