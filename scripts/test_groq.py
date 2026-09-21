import os

import requests
from dotenv import load_dotenv

load_dotenv()
GROQ_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_KEY:
    raise SystemExit("GROQ_API_KEY is not set")
headers = {"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"}

# Test with llama-3.1-8b-instant
resp = requests.post(
    "https://api.groq.com/openai/v1/chat/completions",
    json={
        "model": "llama-3.1-8b-instant",
        "messages": [{"role": "user", "content": "Say hello in exactly 5 words."}],
        "max_tokens": 20,
        "temperature": 0.0,
    },
    headers=headers,
    timeout=15,
)
print(f"Status: {resp.status_code}")
if resp.status_code == 200:
    content = resp.json()["choices"][0]["message"]["content"]
    print(f"Response: {content}")
else:
    print(f"Error: {resp.text[:500]}")
