import os

import requests
from dotenv import load_dotenv

load_dotenv()
GROQ_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_KEY:
    raise SystemExit("GROQ_API_KEY is not set")
headers = {"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"}

# List available models
resp = requests.get("https://api.groq.com/openai/v1/models", headers=headers, timeout=15)
print(f"Status: {resp.status_code}")
if resp.status_code == 200:
    models = resp.json()["data"]
    print(f"Available models ({len(models)}):")
    for m in models:
        print(f"  - {m['id']}")
else:
    print(f"Error: {resp.text[:500]}")
