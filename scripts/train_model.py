"""Train the shadow model and write model.json. It runs beside the rules and never changes a decision.

    python scripts/train_model.py --simulated            train on the benchmark's simulated tuning scenarios
    python scripts/train_model.py --labels labels.json   train on reviewer outcomes saved from GET /risk/labels

With --labels it refuses to train on fewer than 200 labelled payments or fewer than 30 of either outcome:
below that a model is noise. "not_upheld" is treated as not-fraud, which is a known source of label noise.
The version written into the file names the data source, the ruleset and the date, and is stored in every
sealed decision the model scores, so results can always be traced to the exact model.
"""

from __future__ import annotations

import importlib.util
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.risk import model as shadow  # noqa: E402
from app.risk.engine import RULESET_VERSION, decide  # noqa: E402


def simulated_rows(seed: int) -> list[tuple[list[float], int]]:
    spec = importlib.util.spec_from_file_location("benchmark", ROOT / "scripts" / "benchmark.py")
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    r = random.Random(seed)  # noqa: S311 - simulation, not security
    rows = []
    for label, scenarios in ((0, bench.LEGIT), (1, bench.FRAUD)):
        for make, n in scenarios:
            rows += [(shadow.features_of(decide(make(r))), label) for _ in range(n)]
    return rows


def label_rows(path: Path) -> list[tuple[list[float], int]]:
    data = json.loads(path.read_text(encoding="utf-8"))["rows"]
    rows = []
    for row in data:
        fired = set(row["signals_fired"])
        rows.append(([1.0 if f in fired else 0.0 for f in shadow.FEATURES], 1 if row["label"] == "fraud" else 0))
    fraud = sum(y for _, y in rows)
    if len(rows) < 200 or fraud < 30 or len(rows) - fraud < 30:
        sys.exit(f"refusing: {len(rows)} labels ({fraud} fraud) is too few to train on (need 200, with 30 of each)")
    return rows


if __name__ == "__main__":
    if "--simulated" in sys.argv:
        rows, source = simulated_rows(seed=777), "simulated"
    elif "--labels" in sys.argv and sys.argv.index("--labels") + 1 < len(sys.argv):
        rows, source = label_rows(Path(sys.argv[sys.argv.index("--labels") + 1])), "reviewer-labels"
    else:
        sys.exit(__doc__)
    model = shadow.train(rows)
    model.update(
        version=f"lr-{source}-{RULESET_VERSION}-{datetime.now(timezone.utc):%Y%m%d}",
        trained_on=source,
        rows=len(rows),
        ruleset_version=RULESET_VERSION,
        threshold=0.5,
    )
    (ROOT / "model.json").write_text(json.dumps(model, indent=1) + "\n", encoding="utf-8")
    top = sorted(zip(model["features"], model["weights"], strict=True), key=lambda t: -abs(t[1]))[:8]
    print(f"wrote model.json: {model['version']} from {len(rows)} rows")
    print("largest weights:", ", ".join(f"{f} {w:+.2f}" for f, w in top))
