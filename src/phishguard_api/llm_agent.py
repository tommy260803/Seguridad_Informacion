import asyncio
import json
import os
import re
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()


def _parse_response(text: str) -> dict[str, Any]:
    cleaned = re.sub(r"^```json\s*|^```\s*|```$", "", text.strip(), flags=re.MULTILINE).strip()
    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict) or not isinstance(parsed.get("probability"), (int, float)):
        raise ValueError("response did not contain numeric probability")
    parsed["probability"] = max(0.0, min(1.0, float(parsed["probability"])))
    return parsed


async def analyze_phishing_with_llm(url: str, html_bytes: bytes) -> tuple[dict[str, Any] | None, dict[str, str] | None]:
    """Return structured LLM evidence, or a categorized error after bounded fallbacks."""
    html = html_bytes.decode("utf-8", errors="ignore")
    text = re.sub(r"<(script|style).*?>.*?</\1>", "", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()[:2000] or "Sin texto"
    prompt = f"""Eres un analista experto en ciberseguridad. Analiza si esta pagina es phishing o estafa.
URL: {url}
Texto extraido: {text}
Responde solo JSON valido con probability (float 0.0 a 1.0), brand_spoofed, reason, page_purpose, attack_scenarios y recommendation. Basa las conclusiones exclusivamente en el texto suministrado; si no hay evidencia de formularios, pagos o descargas, no los inventes."""
    timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "10"))
    attempts = max(1, int(os.getenv("LLM_MAX_ATTEMPTS", "2")))

    def execute() -> tuple[dict[str, Any] | None, dict[str, str] | None]:
        gemini_key = os.getenv("GEMINI_API_KEY")
        gemini_errors: list[str] = []
        if gemini_key:
            models = [value.strip() for value in os.getenv("GEMINI_MODELS", "gemini-3.5-flash-lite,gemini-2.5-flash").split(",") if value.strip()]
            for model in models[:attempts]:
                try:
                    response = requests.post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}", json={"contents": [{"parts": [{"text": prompt}]}]}, headers={"Content-Type": "application/json"}, timeout=timeout)
                    if response.status_code == 200:
                        response_text = response.json().get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "{}")
                        return _parse_response(response_text), None
                    kind = "quota" if response.status_code == 429 else "provider_error"
                    gemini_errors.append(f"{model}:{kind}:{response.status_code}")
                except Exception as exc:
                    gemini_errors.append(f"{model}:timeout_or_invalid_response:{str(exc)[:120]}")
        else:
            gemini_errors.append("not_configured")

        groq_key = os.getenv("GROQ_API_KEY")
        if not groq_key:
            return None, {"provider": "gemini", "kind": "unavailable", "message": "; ".join(gemini_errors)[:512]}
        try:
            response = requests.post("https://api.groq.com/openai/v1/chat/completions", json={"model": os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"), "messages": [{"role": "user", "content": prompt}], "temperature": 0.0, "max_tokens": 300}, headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"}, timeout=timeout)
            if response.status_code != 200:
                kind = "quota" if response.status_code == 429 else "model_unavailable" if response.status_code == 400 else "provider_error"
                return None, {"provider": "groq", "kind": kind, "message": response.text[:512]}
            response_text = response.json().get("choices", [{}])[0].get("message", {}).get("content", "{}")
            return _parse_response(response_text), None
        except Exception as exc:
            return None, {"provider": "groq", "kind": "timeout_or_invalid_response", "message": str(exc)[:512]}

    return await asyncio.to_thread(execute)
