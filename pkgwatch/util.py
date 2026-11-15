"""Small shared helpers."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utcnow() -> datetime:
    return datetime.now(UTC)


def parse_ts(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp (``Z`` suffix allowed); naive values are taken as UTC."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path: Path | str, default: Any = None) -> Any:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return default


def write_json(path: Path | str, data: Any, *, compact: bool = False) -> None:
    """Write JSON atomically with stable key order, so unchanged data produces no diff."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        if compact:
            json.dump(data, fh, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        else:
            json.dump(data, fh, ensure_ascii=False, sort_keys=True, indent=1)
        fh.write("\n")
    os.replace(tmp, target)
