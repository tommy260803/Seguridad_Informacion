import os
import json
import re
import requests
import asyncio

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
    
    prompt = f"""Eres un analista experto en ciberseguridad. Analiza si la siguiente página es un sitio de phishing.
URL visitada: {url}

Texto extraído de la página (parcial):
{safe_text}

Responde ÚNICAMENTE con un objeto JSON válido (sin markdown ni comillas invertidas) con esta estructura exacta:
{{
    "probability": 1.0,
    "brand_spoofed": "Nombre del banco o empresa suplantada (o 'Desconocida')",
    "reason": "Breve razón técnica (ej. 'Dominio sospechoso imitando a BBVA')",
    "recommendation": "Un consejo para el usuario (ej. 'Si recibiste este enlace por mensaje, elimínalo y repórtalo. Los bancos no solicitan contraseñas por enlaces.')"
}}
Donde probability es un float del 0.0 (seguro) al 1.0 (phishing)."""

    def fetch_gemini():
        gemini_key = os.environ.get("GEMINI_API_KEY")
        if not gemini_key:
            return None
            
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key={gemini_key}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        
        try:
            print("Intentando inferencia con Gemini...", flush=True)
            response = requests.post(endpoint, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
            if response.status_code != 200:
                print(f"Error Gemini API: {response.text}", flush=True)
                return None
            data = response.json()
            text_response = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "{}")
            text_clean = text_response.strip().strip('`').replace('json\n', '')
            return json.loads(text_clean)
        except Exception as e:
            print(f"Excepción en Gemini: {e}", flush=True)
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
