"""
Enhanced LLM Agent for PhishGuard
Uses Groq/Gemini for explainability and brand classification.
"""
import asyncio
import json
import os
import re
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

# Enhanced prompt for better explainability
ANALYSIS_PROMPT = """Eres un analista experto en ciberseguridad y phishing. Analiza esta URL y proporciona un diagnóstico detallado.

## URL a analizar
{url}

## Información del análisis automático
- Probabilidad M0 (análisis léxico): {m0_prob:.1%}
- Análisis de marca: {brand_info}
- Reglas detectadas: {rules_info}

## Instrucciones
Analiza la URL considerando:
1. **Suplantación de marca**: ¿El dominio parece intentar imitar una marca legítima? (ej: facebuuk.com → Facebook)
2. **Patrones sospechosos**: Subdominios excesivos, TLDs raros, caracteres homográficos
3. **Propósito probable**: ¿Qué tipo de ataque podría ser? (credential harvesting, malware, estafa)
4. **Nivel de riesgo**: Del 0 al 100, ¿qué tan peligroso es?

## Respuesta requerida (JSON válido)
Responde SOLO con JSON válido (sin markdown, sin texto adicional):
{{
    "probability": 0.85,
    "brand_spoofed": "Facebook",
    "threat_type": "Typosquatting",
    "reason": "El dominio facebuuk.com utiliza una técnica de typosquatting para suplantar a Facebook, cambiando la 'k' por 'uu'",
    "page_purpose": "Portal diseñado para robar credenciales de Facebook mediante formulario de inicio de sesión falso",
    "attack_scenarios": [
        "Robo de credenciales de Facebook",
        "Acceso no autorizado a cuentas",
        "Difusión de malware a contactos"
    ],
    "recommendation": "No ingreses tus credenciales. Cierra esta página inmediatamente.",
    "confidence": 95
}}"""

# Prompt for brand classification
BRAND_PROMPT = """Identifica qué marca o servicio legítimo está siendo suplantado en esta URL.

URL: {url}

Responde SOLO con JSON válido:
{{
    "brand_name": "Nombre de la marca",
    "confidence": 85,
    "technique": "Tipo de suplantación (typosquatting, homograph, subdomain, etc)"
}}"""


def _parse_json_response(text: str) -> Optional[Dict[str, Any]]:
    """Parse JSON from LLM response, handling common formatting issues."""
    # Remove markdown code blocks
    cleaned = re.sub(r"^```json\s*|^```\s*|```$", "", text.strip(), flags=re.MULTILINE).strip()
    
    # Try to find JSON object in the response
    json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', cleaned, re.DOTALL)
    if json_match:
        try:
            parsed = json.loads(json_match.group())
            return parsed
        except json.JSONDecodeError:
            pass
    
    # Try parsing the entire cleaned text
    try:
        parsed = json.loads(cleaned)
        return parsed
    except json.JSONDecodeError:
        return None


def _build_context(
    url: str,
    m0_prob: float,
    brand_analysis: Optional[Dict],
    rules_analysis: Optional[Dict]
) -> Dict[str, str]:
    """Build context strings for the prompt."""
    # M0 probability
    m0_prob_str = f"{m0_prob:.1%}"
    
    # Brand info
    if brand_analysis and brand_analysis.get("is_brand_impersonation"):
        brand_info = f"Detectada suplantación de {brand_analysis.get('closest_brand', 'desconocida')} "
        brand_info += f"(similitud: {brand_analysis.get('brand_similarity', 0):.0%}, "
        brand_info += f"distancia Levenshtein: {brand_analysis.get('min_brand_distance', 'N/A')})"
    else:
        brand_info = "No se detectó suplantación de marca conocida"
    
    # Rules info
    if rules_analysis and rules_analysis.get("triggered_rules"):
        rules_list = [r["rule"] for r in rules_analysis["triggered_rules"]]
        rules_info = f"Reglas activadas: {', '.join(rules_list)}"
    else:
        rules_info = "Sin reglas sospechosas activadas"
    
    return {
        "m0_prob": m0_prob_str,
        "brand_info": brand_info,
        "rules_info": rules_info
    }


async def analyze_with_llm(
    url: str,
    m0_prob: float,
    brand_analysis: Optional[Dict] = None,
    rules_analysis: Optional[Dict] = None
) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, str]]]:
    """
    Enhanced LLM analysis for explainability.
    
    Returns:
        Tuple of (analysis_result, error_info)
        - analysis_result: Dict with probability, brand_spoofed, reason, etc.
        - error_info: Dict with provider, kind, message if error occurred
    """
    # Build context
    context = _build_context(url, m0_prob, brand_analysis, rules_analysis)
    
    # Build prompt
    prompt = ANALYSIS_PROMPT.format(
        url=url,
        m0_prob=context["m0_prob"],
        brand_info=context["brand_info"],
        rules_info=context["rules_info"]
    )
    
    # Get API keys
    groq_key = os.getenv("GROQ_API_KEY")
    gemini_key = os.getenv("GEMINI_API_KEY")
    
    timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "15"))
    attempts = max(1, int(os.getenv("LLM_MAX_ATTEMPTS", "2")))
    
    def execute_groq() -> tuple[Optional[Dict], Optional[Dict]]:
        if not groq_key:
            return None, {"provider": "groq", "kind": "not_configured", "message": "GROQ_API_KEY not set"}
        
        try:
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                json={
                    "model": os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"),
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens": 600
                },
                headers={
                    "Authorization": f"Bearer {groq_key}",
                    "Content-Type": "application/json"
                },
                timeout=timeout
            )
            
            if response.status_code != 200:
                kind = "quota" if response.status_code == 429 else "provider_error"
                return None, {"provider": "groq", "kind": kind, "message": response.text[:512]}
            
            response_text = response.json().get("choices", [{}])[0].get("message", {}).get("content", "{}")
            parsed = _parse_json_response(response_text)
            
            if parsed and "probability" in parsed:
                # Ensure probability is valid
                parsed["probability"] = max(0.0, min(1.0, float(parsed["probability"])))
                return parsed, None
            else:
                return None, {"provider": "groq", "kind": "invalid_response", "message": "No valid JSON with probability"}
                
        except Exception as exc:
            return None, {"provider": "groq", "kind": "timeout_or_invalid_response", "message": str(exc)[:512]}
    
    def execute_gemini() -> tuple[Optional[Dict], Optional[Dict]]:
        if not gemini_key:
            return None, {"provider": "gemini", "kind": "not_configured", "message": "GEMINI_API_KEY not set"}
        
        models = [m.strip() for m in os.getenv("GEMINI_MODELS", "gemini-2.0-flash").split(",") if m.strip()]
        
        for model in models[:attempts]:
            try:
                response = requests.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}",
                    json={"contents": [{"parts": [{"text": prompt}]}]},
                    headers={"Content-Type": "application/json"},
                    timeout=timeout
                )
                
                if response.status_code == 200:
                    response_text = response.json().get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "{}")
                    parsed = _parse_json_response(response_text)
                    
                    if parsed and "probability" in parsed:
                        parsed["probability"] = max(0.0, min(1.0, float(parsed["probability"])))
                        return parsed, None
                
                kind = "quota" if response.status_code == 429 else "provider_error"
                continue  # Try next model
                
            except Exception as exc:
                continue  # Try next model
        
        return None, {"provider": "gemini", "kind": "all_models_failed", "message": "All Gemini models failed"}
    
    # Try Groq first (faster), then Gemini
    result, error = await asyncio.to_thread(execute_groq)
    if result:
        return result, None
    
    # Fallback to Gemini
    result, gemini_error = await asyncio.to_thread(execute_gemini)
    if result:
        return result, None
    
    # Both failed
    return None, error or gemini_error


async def classify_brand(url: str) -> Optional[Dict[str, Any]]:
    """
    Use LLM to classify which brand is being impersonated.
    
    Returns:
        Dict with brand_name, confidence, technique
    """
    groq_key = os.getenv("GROQ_API_KEY")
    if not groq_key:
        return None
    
    prompt = BRAND_PROMPT.format(url=url)
    timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "10"))
    
    def execute():
        try:
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                json={
                    "model": os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"),
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens": 200
                },
                headers={
                    "Authorization": f"Bearer {groq_key}",
                    "Content-Type": "application/json"
                },
                timeout=timeout
            )
            
            if response.status_code == 200:
                response_text = response.json().get("choices", [{}])[0].get("message", {}).get("content", "{}")
                return _parse_json_response(response_text)
            
            return None
        except Exception:
            return None
    
    return await asyncio.to_thread(execute)
