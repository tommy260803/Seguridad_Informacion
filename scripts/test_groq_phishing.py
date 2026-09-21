import json
import os
import re
import sys

import requests
from dotenv import load_dotenv

sys.stdout.reconfigure(encoding='utf-8')

load_dotenv()
GROQ_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_KEY:
    raise SystemExit("GROQ_API_KEY is not set")
headers = {"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"}

prompt = """Eres un analista experto en ciberseguridad. Analiza si esta pagina es phishing o estafa.
URL: https://secure-bankofamerica.com.login-verify.xyz/account
Texto extraido: Bank of America - Please verify your account. Enter your username and password to continue. Secure connection.
Responde solo JSON valido con probability (float 0.0 a 1.0), brand_spoofed, reason, page_purpose, attack_scenarios y recommendation."""

resp = requests.post(
    "https://api.groq.com/openai/v1/chat/completions",
    json={
        "model": "openai/gpt-oss-20b",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0,
        "max_tokens": 300,
    },
    headers=headers,
    timeout=15,
)
print(f"Status: {resp.status_code}")
if resp.status_code == 200:
    content = resp.json()["choices"][0]["message"]["content"]
    print(f"Raw response: {content[:500]}")
    cleaned = re.sub(r"^```json\s*|^```\s*|```$", "", content.strip(), flags=re.MULTILINE).strip()
    parsed = json.loads(cleaned)
    print(f"\nParsed: probability={parsed.get('probability')}, brand={parsed.get('brand_spoofed')}, rec={parsed.get('recommendation')}")
else:
    print(f"Error: {resp.text[:500]}")
