const urlParams = new URLSearchParams(window.location.search);
let targetUrl = urlParams.get('url');
const jobId = urlParams.get('jobId');

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
}

// Botón para cerrar pestaña de manera segura
document.getElementById('btn-close').addEventListener('click', () => {
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

// Helper seguro para obtener el endpoint
function getEndpoint() {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    return chrome.storage.local.get({ endpoint: 'http://localhost:8080/analyses' })
      .then(res => res.endpoint || 'http://localhost:8080/analyses')
      .catch(() => 'http://localhost:8080/analyses');
  }
  return Promise.resolve('http://localhost:8080/analyses');
}

// Botón para ignorar la advertencia
document.getElementById('btn-ignore').addEventListener('click', () => {
  const finalUrl = targetUrl || document.getElementById('url-display').textContent;
  if (finalUrl && !finalUrl.startsWith('Cargando')) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get({ allowed_urls: [] }).then(({ allowed_urls }) => {
        const allowed = allowed_urls || [];
        try {
          const origin = new URL(finalUrl).origin;
          if (!allowed.includes(origin)) allowed.push(origin);
        } catch (e) {
          if (!allowed.includes(finalUrl)) allowed.push(finalUrl);
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

// Cargar información completa del análisis desde el backend
if (jobId) {
  getEndpoint().then(endpoint => {
    const base = endpoint.replace(/\/analyses\/?$/, '');
    fetch(`${base}/analyses/${jobId}`)
      .then(res => {
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        return res.json();
      })
      .then(data => {
        // 1. Asegurar URL real
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

        // 2. Probabilidad y Nivel de Riesgo
        const prob = Number(data.probability ?? 1.0);
        const probPct = (prob * 100).toFixed(1) + '%';
        
        document.getElementById('prob-val').textContent = `${probPct}`;
        document.getElementById('risk-pct-banner').textContent = probPct;

        const riskEl = document.getElementById('risk-text');
        if (prob >= 0.8) {
          riskEl.textContent = 'CRÍTICO';
          riskEl.style.color = '#dc2626';
        } else if (prob >= 0.5) {
          riskEl.textContent = 'MEDIO';
          riskEl.style.color = '#d97706';
        } else {
          riskEl.textContent = 'BAJO';
          riskEl.style.color = '#16a34a';
        }

        // 3. Extraer detalles de la IA (Gemini) y del modelo base (M0)
        let llmDetails = null;
        let m0Prob = null;
        if (Array.isArray(data.evidence)) {
          for (const ev of data.evidence) {
            if (ev.source === 'LLM' && ev.details) {
              llmDetails = ev.details;
            }
            if (ev.source === 'M0' && ev.value !== undefined) {
              m0Prob = Number(ev.value);
            }
          }
        }

        // 4. Integrar diagnósticos y recomendaciones de la IA
        if (llmDetails) {
          // Marca suplantada
          if (llmDetails.brand_spoofed && llmDetails.brand_spoofed !== 'Desconocida') {
            document.getElementById('brand-val').textContent = llmDetails.brand_spoofed;
            document.getElementById('threat-val').textContent = `Suplantación de ${llmDetails.brand_spoofed} (Typosquatting)`;
            document.getElementById('main-title').textContent = `Peligro: Suplantación de ${llmDetails.brand_spoofed}`;
          } else {
            document.getElementById('brand-val').textContent = 'Dominio de riesgo genérico';
            document.getElementById('threat-val').textContent = 'Sitio sospechoso de phishing';
          }

          // Razón por la que se bloqueó
          if (llmDetails.reason) {
            document.getElementById('main-desc').innerHTML = `<b>Diagnóstico de la IA:</b> ${llmDetails.reason}<br><span style="color:#64748b; font-size:13px; margin-top:4px; display:inline-block;">Se recomienda no abrir ni ingresar contraseñas o datos personales.</span>`;
          }

          // Recomendación personalizada de la IA
          if (llmDetails.recommendation) {
            document.getElementById('rec-value').textContent = llmDetails.recommendation;
          }
        } else {
          document.getElementById('brand-val').textContent = 'Patrón de phishing detectado';
          document.getElementById('threat-val').textContent = 'Estructura sospechosa';
          document.getElementById('rec-value').textContent = 'Cierra esta ventana inmediatamente. El sistema ha identificado indicadores coincidentes con portales fraudulentos.';
        }

        // 5. Explicación de por qué se asignó este porcentaje
        let whyDesc = `Se asignó un score de riesgo del ${probPct}. `;
        if (llmDetails && llmDetails.brand_spoofed && llmDetails.brand_spoofed !== 'Desconocida') {
          whyDesc += `El agente inteligente Gemini detectó una técnica activa de suplantación dirigida a "${llmDetails.brand_spoofed}". `;
        }
        if (m0Prob !== null) {
          whyDesc += `El modelo clasificador léxico de URL evaluó la anomalía sintáctica con un puntaje de ${(m0Prob * 100).toFixed(1)}%. `;
        }
        whyDesc += `La coincidencia de ambos modelos concluyó con máxima certeza que se trata de un sitio hostil.`;
        document.getElementById('why-percentage-desc').textContent = whyDesc;

        // 6. Vista previa mediante Captura Segura en Servidor (RBI Headless Screenshot)
        const screenshotUrl = `${base}/screenshots/${jobId}.png`;
        const previewContainer = document.getElementById('preview-container');

        // Indicador inicial de carga mientras el servidor genera la captura con Playwright
        previewContainer.className = 'preview-box';
        previewContainer.style.padding = '32px 20px';
        previewContainer.innerHTML = `
          <div style="font-size: 30px; margin-bottom: 8px;">⏳</div>
          <div class="preview-box-title" style="color: #334155; font-size: 15px;">Generando Captura Segura en Servidor...</div>
          <div class="preview-box-desc" style="color: #64748b; font-size: 13px;">
            El servidor está ejecutando el sitio en un entorno aislado con Playwright para capturar el diseño completo de forma 100% segura.
          </div>
        `;

        fetch(screenshotUrl)
          .then(async res => {
            if (res.ok) {
              previewContainer.classList.remove('preview-box');
              previewContainer.style.padding = '0';
              previewContainer.style.border = '1px solid #cbd5e1';
              previewContainer.style.borderRadius = '10px';
              previewContainer.style.overflow = 'hidden';
              previewContainer.style.background = '#ffffff';
              previewContainer.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.05)';

              previewContainer.innerHTML = `
                <!-- Barra superior de navegador simulado -->
                <div style="background: #0f172a; color: #94a3b8; font-size: 12px; padding: 10px 16px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155;">
                  <div style="display: flex; align-items: center; gap: 10px;">
                    <div style="display: flex; gap: 6px;">
                      <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #ef4444;"></span>
                      <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #f59e0b;"></span>
                      <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #10b981;"></span>
                    </div>
                    <div style="background: #1e293b; padding: 3px 14px; border-radius: 6px; font-family: monospace; color: #e2e8f0; font-size: 11.5px; border: 1px solid #334155; max-width: 480px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                      🔒 ${targetUrl}
                    </div>
                  </div>
                  <div style="display: flex; gap: 8px;">
                    <span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); font-size: 11px;">Captura 100% Inerte</span>
                    <span class="badge" style="background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); font-size: 11px;">Playwright Headless</span>
                  </div>
                </div>

                <!-- Visor de la imagen estática -->
                <div style="max-height: 500px; overflow-y: auto; background: #f8fafc; border-bottom: 1px solid #e2e8f0; text-align: center;">
                  <img src="${screenshotUrl}" alt="Captura segura del sitio" style="width: 100%; height: auto; display: block;">
                </div>

                <!-- Pie informativo de seguridad -->
                <div style="background: #f8fafc; padding: 10px 16px; font-size: 12px; color: #475569; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                  <span>🛡️ <b>Entorno Aislado:</b> El código JavaScript se ejecutó exclusivamente en el servidor. Tu equipo solo visualiza una imagen fotográfica estática.</span>
                  <a href="${screenshotUrl}" target="_blank" style="color: #2563eb; font-weight: 500; font-size: 11.5px; text-decoration: none; display: flex; align-items: center; gap: 4px;">
                    Ver en tamaño completo ↗
                  </a>
                </div>
              `;
            } else {
              // Si falla la captura (ej. dominio caído / DNS NXDOMAIN)
              let errorReason = "El servidor remoto no respondió o el dominio no tiene resolución DNS activa.";
              try {
                const errData = await res.json();
                if (errData && errData.detail && errData.detail.message) {
                  errorReason = errData.detail.message;
                }
              } catch (e) {}

              const analyzedDomain = document.getElementById('domain-val').textContent || targetUrl;
              previewContainer.className = 'preview-box';
              previewContainer.style.padding = '36px 20px';
              previewContainer.innerHTML = `
                <div style="font-size: 34px; margin-bottom: 10px;">🌐⚠️</div>
                <div class="preview-box-title" style="color: #334155; font-size: 15px;">Sitio Inactivo o Dominio Fuera de Línea</div>
                <div class="preview-box-desc" style="max-width: 520px; margin: 0 auto; color: #64748b; font-size: 13px; line-height: 1.5;">
                  No se pudo generar la captura porque el servidor remoto de <b>${analyzedDomain}</b> no respondió a la conexión (sitio caído, suspendido o sin registros DNS).
                  <br><span style="display: inline-block; margin-top: 8px; font-size: 11.5px; color: #94a3b8;">
                    PhishGuard bloqueó el acceso preventivamente basándose en el análisis léxico y la detección de suplantación de la IA.
                  </span>
                </div>
              `;
            }
          })
          .catch(err => {
            console.error('Error al solicitar captura de pantalla:', err);
          });

        // 7. Análisis Contextual en Profundidad y Escenarios de Riesgo
        const purposeEl = document.getElementById('page-purpose-text');
        const scenariosGrid = document.getElementById('scenarios-grid');

        const brand = (llmDetails && llmDetails.brand_spoofed && llmDetails.brand_spoofed !== 'Desconocida') 
          ? llmDetails.brand_spoofed 
          : 'la entidad suplantada';

        // 7.1 Propósito detectado de la página
        if (llmDetails && llmDetails.page_purpose) {
          purposeEl.textContent = llmDetails.page_purpose;
        } else if (llmDetails && llmDetails.reason) {
          purposeEl.textContent = `Este portal simula ser una interfaz de ${brand} diseñada para captar la atención del usuario mediante pretextos de acceso, verificación o transacciones fraudulentas.`;
        } else {
          purposeEl.textContent = `Portal sospechoso con estructura fraudulenta orientada a la extracción no autorizada de datos personales.`;
        }

        // 7.2 Escenarios de Ataque e Impacto
        let scenarios = [];
        if (llmDetails && Array.isArray(llmDetails.attack_scenarios) && llmDetails.attack_scenarios.length > 0) {
          scenarios = llmDetails.attack_scenarios;
        } else {
          // Escenarios contextuales inferidos según la marca o tipo de servicio
          const brandLower = brand.toLowerCase();
          if (brandLower.includes('face') || brandLower.includes('insta') || brandLower.includes('meta') || brandLower.includes('social') || brandLower.includes('google') || brandLower.includes('tiktok')) {
            scenarios = [
              {
                title: "Secuestro Total de Cuenta",
                desc: "Los ciberdelincuentes obtienen control de tu perfil, fotos, mensajes privados y contraseñas de acceso."
              },
              {
                title: "Fraude y Extorsión a Contactos",
                desc: "Usan tu identidad para enviar mensajes urgentes a tus amigos o familiares pidiéndoles dinero o enviando malware."
              },
              {
                title: "Compromiso de Cuentas Vinculadas",
                desc: "Intentos automatizados de acceso a otros servicios o correos donde reutilices la misma contraseña."
              }
            ];
          } else if (brandLower.includes('banco') || brandLower.includes('bbva') || brandLower.includes('interbank') || brandLower.includes('bcp') || brandLower.includes('scotia') || brandLower.includes('visa') || brandLower.includes('mastercard') || brandLower.includes('pay')) {
            scenarios = [
              {
                title: "Robo de Fondos y Transferencias",
                desc: "Captura inmediata de tus claves de acceso, token digital o números de tarjeta para vaciar tu saldo."
              },
              {
                title: "Clonación de Tarjetas (Carding)",
                desc: "Extracción del número de tarjeta, fecha de vencimiento y código CVV para realizar compras online no autorizadas."
              },
              {
                title: "Suplantación para Préstamos Falsos",
                desc: "Uso de tus datos personales para solicitar créditos o abrir cuentas falsas en entidades financieras."
              }
            ];
          } else if (brandLower.includes('claro') || brandLower.includes('movistar') || brandLower.includes('entel') || brandLower.includes('telecom')) {
            scenarios = [
              {
                title: "Robo de Línea Móvil (SIM Swapping)",
                desc: "Intento de obtener datos suficientes para duplicar tu chip y desviar tus SMS de autenticación bancaria."
              },
              {
                title: "Exfiltración de Datos de Facturación",
                desc: "Acceso a historiales, nombres completos, números de documento (DNI) y domicilio para extorsiones dirigidas."
              },
              {
                title: "Cargos Fraudulentos en Recibo",
                desc: "Suscripción no autorizada a servicios premium con cargo directo a la línea telefónica."
              }
            ];
          } else if (brandLower.includes('marvel') || brandLower.includes('crypto') || brandLower.includes('coin') || brandLower.includes('wallet') || brandLower.includes('token') || brandLower.includes('nft') || brandLower.includes('binance') || brandLower.includes('metamask')) {
            scenarios = [
              {
                title: "Drenado de Billetera (Wallet Drainer)",
                desc: "La firma de transacciones falsas otorga permisos para vaciar automáticamente tus tokens USDT, ETH y criptomonedas."
              },
              {
                title: "Pérdida Irreversible de Activos",
                desc: "En la red blockchain las transferencias son definitivas y anónimas; los fondos no pueden ser devueltos ni cancelados."
              },
              {
                title: "Compromiso de Frase Semilla",
                desc: "Si solicitan tus 12 o 24 palabras de recuperación, los atacantes se adueñan permanentemente de tu billetera."
              }
            ];
          } else {
            scenarios = [
              {
                title: "Captura y Registro de Datos",
                desc: "Cualquier texto, credencial o documento introducido en los formularios es grabado por el servidor del atacante."
              },
              {
                title: "Comercialización en Mercados Ilícitos",
                desc: "Tus datos personales pueden ser vendidos a terceros para campañas de spam, fraude y extorsión."
              },
              {
                title: "Ataque en Cascada (Credential Stuffing)",
                desc: "Pruebas masivas con robots para vulnerar tus otras cuentas utilizando la misma combinación de correo y clave."
              }
            ];
          }
        }

        if (scenariosGrid) {
          scenariosGrid.innerHTML = scenarios.map((sc, idx) => `
            <div class="scenario-item">
              <div class="scenario-badge">${idx + 1}</div>
              <div class="scenario-content">
                <span class="scenario-title">${sc.title}</span>
                <p class="scenario-desc">${sc.desc}</p>
              </div>
            </div>
          `).join('');
        }
      })
      .catch(err => {
        console.error('Error cargando detalles del trabajo:', err);
      });
  });
}
