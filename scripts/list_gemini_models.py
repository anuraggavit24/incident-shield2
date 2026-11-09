"""List the Gemini models your GEMINI_API_KEY can call with generateContent.

Usage:  python scripts/list_gemini_models.py
Pick one and set GEMINI_MODEL in .env (default: gemini-3.8-flash).
"""

import os
import sys

import httpx
from dotenv import load_dotenv

load_dotenv()
key = os.getenv("GEMINI_API_KEY", "").strip()
if not key:
    sys.exit("GEMINI_API_KEY is not set in .env")
response = httpx.get(
    "https://generativelanguage.googleapis.com/v1beta/models",
    params={"pageSize": 200},
    headers={"x-goog-api-key": key},
    timeout=20,
)
if response.status_code != 200:
    sys.exit(f"HTTP {response.status_code}: {response.text[:300]}")
configured = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
names = sorted(
    m["name"].removeprefix("models/")
    for m in response.json().get("models", [])
    if "generateContent" in m.get("supportedGenerationMethods", [])
)
for name in names:
    marker = "  <- GEMINI_MODEL" if name == configured else ""
    print(f"{name}{marker}")
if configured not in names:
    print(f"\nGEMINI_MODEL={configured} is NOT available to this key. Pick a 'flash' model from the list.")
