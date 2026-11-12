"""A small model that runs BESIDE the rules, in shadow mode. It never changes a decision.

What it is: logistic regression over "which signals fired" (one yes/no feature per signal), trained by
scripts/train_model.py. Pure Python, no extra dependency. Its probability is stored inside each sealed
decision as `shadow_model`, so GET /risk/shadow can later show where it and the rules disagreed, and what
reviewers decided in those cases. That is how a model earns the right to be switched on: weeks of shadow
results on real outcomes, not a benchmark.

What it is not: evidence of better detection. Until there are enough real reviewer labels, the only training
data is the simulated benchmark, and a model trained on that mostly learns the rules back.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any

from .engine import SIGNALS

FEATURES = tuple(s.id for s in SIGNALS)
_loaded: dict[str, Any] = {"path": None, "mtime": None, "model": None}


def features_of(decision: dict[str, Any]) -> list[float]:
    fired = {f["name"] for f in decision["signals_fired"]}
    return [1.0 if f in fired else 0.0 for f in FEATURES]


def _sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


def predict(model: dict[str, Any], x: list[float]) -> float:
    weights = dict(zip(model["features"], model["weights"], strict=True))
    z = model["bias"] + sum(weights.get(f, 0.0) * v for f, v in zip(FEATURES, x, strict=True))
    return _sigmoid(z)


def train(
    rows: list[tuple[list[float], int]], epochs: int = 300, rate: float = 0.5, l2: float = 0.01
) -> dict[str, Any]:
    """Batch gradient descent with L2. rows = [(features, label 1=fraud / 0=not)]. Deterministic."""
    n, width = len(rows), len(FEATURES)
    w, b = [0.0] * width, 0.0
    for _ in range(epochs):
        gw, gb = [0.0] * width, 0.0
        for x, y in rows:
            err = _sigmoid(b + sum(wi * xi for wi, xi in zip(w, x, strict=True))) - y
            gb += err
            for i, xi in enumerate(x):
                if xi:
                    gw[i] += err * xi
        b -= rate * gb / n
        w = [wi - rate * (gi / n + l2 * wi) for wi, gi in zip(w, gw, strict=True)]
    return {"features": list(FEATURES), "weights": [round(v, 5) for v in w], "bias": round(b, 5)}


def load() -> dict[str, Any] | None:
    """The model named by RISK_MODEL_PATH (default: model.json next to the app), or None. Reloaded when the
    file changes. A file that doesn't parse or doesn't match is ignored: shadow mode must never break a payment."""
    path = Path(os.getenv("RISK_MODEL_PATH", "model.json"))
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    if _loaded["path"] == str(path) and _loaded["mtime"] == mtime:
        return _loaded["model"]
    try:
        model = json.loads(path.read_text(encoding="utf-8"))
        ok = (
            isinstance(model.get("version"), str)
            and len(model["features"]) == len(model["weights"])
            and all(isinstance(v, (int, float)) for v in [*model["weights"], model["bias"]])
        )
    except (ValueError, KeyError, TypeError, OSError):
        ok, model = False, None
    _loaded.update(path=str(path), mtime=mtime, model=model if ok else None)
    return _loaded["model"]


def shadow_score(decision: dict[str, Any]) -> dict[str, Any] | None:
    """What the model would have said. Recorded, never acted on."""
    model = load()
    if model is None:
        return None
    try:
        p = predict(model, features_of(decision))
    except (ValueError, KeyError, TypeError):
        return None
    return {"version": model["version"], "p_fraud": round(p, 4), "would_slow": p >= model.get("threshold", 0.5)}
