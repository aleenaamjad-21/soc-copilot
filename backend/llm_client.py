"""
llm_client.py
One shared LLM call function using Groq instead of Gemini — put this in backend/,
then have every agent import call_llm() from here instead of each having its own
Gemini call. Groq's API is OpenAI-compatible, so this is a plain chat completion call.

Get a free key at https://console.groq.com/keys, add to .env:
    GROQ_API_KEY=your-key-here
"""

import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = "openai/gpt-oss-20b"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def call_llm(prompt: str, retries: int = 3, delay: int = 3) -> str:
    """
    Sends a prompt to Groq and returns the raw text response.
    Drop-in replacement for whatever _call_gemini-style function each agent
    currently has — same retry-with-backoff pattern, same "return raw text,
    let the caller parse JSON" contract.
    """
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY not set — add it to your .env file.")

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
    }

    for attempt in range(retries):
        response = requests.post(GROQ_URL, headers=headers, json=payload, timeout=30)

        if response.status_code == 200:
            data = response.json()
            return data["choices"][0]["message"]["content"]

        if response.status_code in (429, 500, 502, 503) and attempt < retries - 1:
            time.sleep(delay)
            continue

        raise RuntimeError(f"Groq API error {response.status_code}: {response.text}")

    raise RuntimeError("Groq API failed after retries")