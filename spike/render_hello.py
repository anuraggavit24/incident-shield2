"""Minimal service for measuring Render's free-tier cold start. No credentials, no PayPal.

Render start command:  uvicorn spike.render_hello:app --host 0.0.0.0 --port $PORT
"""

from __future__ import annotations

import time

from fastapi import FastAPI

STARTED_AT = time.time()
app = FastAPI(title="Incident Shield - cold start probe")


@app.get("/health")
def health() -> dict[str, float]:
    # process_age_s near zero on the first request after idle = the instance was just started (cold).
    return {"process_age_s": round(time.time() - STARTED_AT, 1)}
