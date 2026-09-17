import os
import json
import re
import requests
import asyncio
from dotenv import load_dotenv

load_dotenv()

async def analyze_phishing_with_llm(url: str, html_bytes: bytes) -> float:
    """Envía la URL y el texto al LLM para determinar probabilidad de phishing. Intenta Gemini primero y luego Groq."""
    
    # Extraer texto básico limpiando las etiquetas HTML
    html_str = html_bytes.decode("utf-8", errors="ignore")
    # Limpiar scripts y estilos rudimentariamente
    html_str = re.sub(r"<(script|style).*?>.*?</\1>", "", html_str, flags=re.DOTALL | re.IGNORECASE)
    text_content = re.sub(r"<[^>]+>", " ", html_str)
    text_content = re.sub(r"\s+", " ", text_content).strip()
    
    # Recortar el texto para no exceder tokens
    safe_text = text_content[:2000] if text_content else "Sin texto"
    
    prompt = f"""Eres un analista experto en ciberseguridad. Analiza si la siguiente página es un sitio de phishing o estafa.
URL visitada: {url}

Texto extraído de la página (parcial):
{safe_text}

Responde ÚNICAMENTE con un objeto JSON válido (sin markdown ni comillas invertidas) con esta estructura exacta:
{{
    "probability": 1.0,
    "brand_spoofed": "Nombre del banco, red social o empresa suplantada (o 'Desconocida')",
    "reason": "Breve razón técnica del engaño (ej. 'Dominio typosquatting que imita el acceso a Facebook')",
    "page_purpose": "Explicación breve (1 a 2 frases) de qué trata este sitio según el texto extraído y qué intenta simular.",
    "attack_scenarios": [
        {{
            "title": "Consecuencia 1 (ej. 'Robo de credenciales de acceso')",
            "desc": "Qué le ocurre directamente a los datos que el usuario introduzca en los campos de esta página."
        }},
        {{
            "title": "Consecuencia 2 (ej. 'Suplantación de identidad')",
            "desc": "Cómo utilizarán los atacantes la información o la cuenta vulnerada."
        }},
        {{
            "title": "Consecuencia 3 (ej. 'Ataque a cuentas vinculadas / Fraude')",
            "desc": "Impacto colateral o riesgo financiero adicional según el tipo de servicio vulnerado."
        }}
    ],
    "recommendation": "Un consejo preventivo para el usuario..."
}}
Donde probability es un float del 0.0 (seguro) al 1.0 (phishing).
IMPORTANTE: Basa 'page_purpose' y 'attack_scenarios' estrictamente en el contenido real de la página (formulario de login, tarjeta de crédito, billetera cripto, descarga, etc.)."""

    def fetch_gemini():
        gemini_key = os.environ.get("GEMINI_API_KEY")
        if not gemini_key:
            return None
            
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        
        for model in ["gemini-3.5-flash-lite", "gemini-2.5-flash"]:
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}"
            try:
                print(f"Intentando inferencia con Gemini ({model})...", flush=True)
                response = requests.post(endpoint, json=payload, headers={"Content-Type": "application/json"}, timeout=20)
                if response.status_code == 200:
                    data = response.json()
                    text_response = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "{}")
                    text_clean = re.sub(r"^```json\s*|^```\s*|```$", "", text_response.strip(), flags=re.MULTILINE).strip()
                    parsed = json.loads(text_clean)
                    print(f"Gemini ({model}) respondió exitosamente: {parsed}", flush=True)
                    return parsed
                else:
                    print(f"Gemini ({model}) retornó status {response.status_code}: {response.text[:120]}", flush=True)
            except Exception as e:
                print(f"Excepción en Gemini ({model}): {e}", flush=True)
        return None

    def fetch_groq():
        groq_key = os.environ.get("GROQ_API_KEY")
        if not groq_key:
            return None
            
        endpoint = "https://api.groq.com/openai/v1/chat/completions"
        payload = {
            "model": "llama3-70b-8192",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
            "max_tokens": 300
        }
        headers = {
            "Authorization": f"Bearer {groq_key}",
            "Content-Type": "application/json"
        }
        
        try:
            print("Intentando inferencia con Groq (Plan B)...", flush=True)
            response = requests.post(endpoint, json=payload, headers=headers, timeout=10)
            if response.status_code != 200:
                print(f"Error Groq API: {response.text}", flush=True)
                return None
            data = response.json()
            text_response = data.get("choices", [{}])[0].get("message", {}).get("content", "{}")
            text_clean = text_response.strip().strip('`').replace('json\n', '')
            return json.loads(text_clean)
        except Exception as e:
            print(f"Excepción en Groq: {e}", flush=True)
            return None

    def execute_models():
        # 1. Intentar con Gemini
        result = fetch_gemini()
        if result is not None:
            print(f"Gemini respondió exitosamente: {result}", flush=True)
            return result
            
        # 2. Si Gemini falla (ej. Rate Limit), intentar con Groq
        print("Gemini falló. Activando fallback a Groq...", flush=True)
        result = fetch_groq()
        if result is not None:
            print(f"Groq respondió exitosamente: {result}", flush=True)
            return result
            
        # 3. Si ambos fallan, devolver None para activar el Fail-Safe de worker.py
        print("Ambos modelos de IA fallaron.", flush=True)
        return None

    return await asyncio.to_thread(execute_models)
