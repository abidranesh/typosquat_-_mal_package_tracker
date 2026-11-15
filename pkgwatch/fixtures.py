"""Load the synthetic fixture corpus used by the tests and by ``pkgwatch.eval``.

Each fixture is one JSON document describing a package: its metadata, the text of its
files, and the finding ids it is expected to trigger. Fixtures are inert data. They
imitate the *shape* of documented attacks, are never executed, and only reference
``example.invalid`` hosts and documentation-range IP addresses.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from .baseline import Baseline, load_baseline
from .config import Config
from .context import PackageContext
from .util import utcnow

DEFAULT_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


@dataclass
class Fixture:
    id: str
    label: str  # "malicious" or "clean"
    pattern: str
    expected: list[str]
    ctx: PackageContext
    allowed: list[str] = field(default_factory=list)  # may fire without counting as FP


def fixture_baselines(directory: Path | str = DEFAULT_DIR) -> dict[str, Baseline]:
    """Small fixed baselines, so fixture results do not drift with the weekly refresh."""
    return {eco: load_baseline(eco, Path(directory) / "baselines") for eco in ("npm", "pypi")}


def build_context(spec: dict[str, Any], config: Config, baseline: Baseline) -> PackageContext:
    meta = dict(spec.get("meta", {}))
    now = utcnow()
    created_days = meta.pop("created_days_ago", 1)
    files = {path: text.encode("utf-8") for path, text in spec.get("files", {}).items()}
    for path, blob in spec.get("files_b64", {}).items():
        files[path] = base64.b64decode(blob)
    return PackageContext(
        ecosystem=spec["ecosystem"],
        name=spec["name"],
        version=spec["version"],
        config=config,
        baseline=baseline,
        package_created_at=now - timedelta(days=created_days),
        published_at=now,
        files=files,
        file_sizes={path: len(data) for path, data in files.items()},
        **meta,
    )


def load_fixtures(
    config: Config, directory: Path | str = DEFAULT_DIR, label: str | None = None
) -> list[Fixture]:
    root = Path(directory)
    baselines = fixture_baselines(root)
    out = []
    for kind in ("malicious", "clean"):
        if label and label != kind:
            continue
        for path in sorted((root / kind).glob("*.json")):
            spec = json.loads(path.read_text(encoding="utf-8"))
            ctx = build_context(spec, config, baselines[spec["ecosystem"]])
            out.append(
                Fixture(
                    path.stem,
                    kind,
                    spec.get("pattern", ""),
                    spec.get("expected", []),
                    ctx,
                    spec.get("allowed", []),
                )
            )
    return out
