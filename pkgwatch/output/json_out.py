"""JSON outputs under ``docs/data``: daily shards, latest, stats and health.

Only *listed* findings are ever written. Packages that were scanned and not flagged
contribute to aggregate counters and nothing else, which keeps repository growth bounded.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..config import Config
from ..context import PackageContext, truncate
from ..scoring import Result
from ..util import iso, parse_ts, read_json, write_json

ECOSYSTEMS = ("npm", "pypi")


@dataclass
class RunCounts:
    """Aggregate numbers for one scan run."""

    scanned: Counter[str] = field(default_factory=Counter)
    flagged: Counter[str] = field(default_factory=Counter)
    high: Counter[str] = field(default_factory=Counter)
    detectors: Counter[str] = field(default_factory=Counter)
    skipped: Counter[str] = field(default_factory=Counter)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def registry_url(ecosystem: str, name: str, version: str | None = None) -> str:
    if ecosystem == "npm":
        base = f"https://www.npmjs.com/package/{quote(name, safe='@/')}"
        return f"{base}/v/{quote(version, safe='')}" if version else base
    base = f"https://pypi.org/project/{quote(name, safe='')}/"
    return f"{base}{quote(version, safe='')}/" if version else base


def make_record(ctx: PackageContext, result: Result, scanned_at: datetime) -> dict[str, Any]:
    """The public, serialisable form of one listed finding."""
    targets = sorted({f.target for f in result.findings if f.target})
    return {
        "key": ctx.key,
        "ecosystem": ctx.ecosystem,
        "name": ctx.name,
        "version": ctx.version,
        "score": result.score,
        "severity": result.severity,
        "published_at": iso(ctx.published_at) if ctx.published_at else None,
        "scanned_at": iso(scanned_at),
        "description": truncate(ctx.description or "", 160),
        "registry_url": registry_url(ctx.ecosystem, ctx.name, ctx.version),
        "targets": targets,
        "findings": [f.to_dict() for f in result.findings],
    }


def record_day(record: dict[str, Any]) -> str:
    """The ``YYYY-MM-DD`` shard a record belongs to (publish date, else scan date)."""
    return (record.get("published_at") or record["scanned_at"])[:10]


def day_path(docs_dir: Path, day: str) -> Path:
    year, month, dom = day.split("-")
    return docs_dir / "data" / "findings" / year / month / f"{dom}.json"


def _sorted(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(records, key=lambda r: (r["scanned_at"], r["key"]), reverse=True)


def merge_shards(docs_dir: Path, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge records into their daily files. Returns the records that were new."""
    by_day: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_day.setdefault(record_day(record), []).append(record)
    fresh = []
    for day, items in by_day.items():
        path = day_path(docs_dir, day)
        existing = {r["key"]: r for r in (read_json(path, {}) or {}).get("findings", [])}
        for record in items:
            if record["key"] not in existing:
                fresh.append(record)
            existing[record["key"]] = record
        write_json(path, {"date": day, "findings": _sorted(list(existing.values()))}, compact=True)
    return fresh


def update_latest(
    docs_dir: Path, records: list[dict[str, Any]], config: Config
) -> list[dict[str, Any]]:
    """Fold records into ``latest.json`` (newest first, capped). Returns the new list."""
    path = docs_dir / "data" / "latest.json"
    merged = {r["key"]: r for r in (read_json(path, {}) or {}).get("findings", [])}
    merged.update({r["key"]: r for r in records})
    latest = _sorted(list(merged.values()))[: int(config.output["latest_max"])]
    updated = latest[0]["scanned_at"] if latest else None
    write_json(path, {"updated": updated, "findings": latest}, compact=True)
    return latest


def _bump(bucket: dict[str, Any], counts: RunCounts, ecosystems: bool) -> None:
    for kind in ("scanned", "flagged", "high"):
        counter: Counter[str] = getattr(counts, kind)
        bucket[kind] = bucket.get(kind, 0) + sum(counter.values())
        if ecosystems:
            per = bucket.setdefault("by_ecosystem", {})
            for eco in ECOSYSTEMS:
                slot = per.setdefault(eco, {"scanned": 0, "flagged": 0, "high": 0})
                slot[kind] += counter.get(eco, 0)


def update_stats(docs_dir: Path, counts: RunCounts, now: datetime, config: Config) -> dict:
    """Add this run to the all-time totals and the rolling daily and hourly windows."""
    path = docs_dir / "data" / "stats.json"
    stats = read_json(path, {}) or {}
    _bump(stats.setdefault("totals", {}), counts, ecosystems=True)
    day = stats.setdefault("daily", {}).setdefault(now.strftime("%Y-%m-%d"), {})
    _bump(day, counts, ecosystems=True)
    detectors = day.setdefault("detectors", {})
    for finding_id, n in counts.detectors.items():
        detectors[finding_id] = detectors.get(finding_id, 0) + n
    _bump(stats.setdefault("hourly", {}).setdefault(now.strftime("%Y-%m-%dT%H"), {}), counts, False)

    day_floor = (now - timedelta(days=int(config.output["stats_window_days"]))).strftime("%Y-%m-%d")
    stats["daily"] = {d: v for d, v in stats["daily"].items() if d > day_floor}
    hour_floor = (now - timedelta(hours=int(config.output["hourly_window_hours"]))).strftime(
        "%Y-%m-%dT%H"
    )
    stats["hourly"] = {h: v for h, v in stats["hourly"].items() if h > hour_floor}
    top: Counter[str] = Counter()
    for bucket in stats["daily"].values():
        top.update(bucket.get("detectors", {}))
    stats["top_detectors"] = [{"id": i, "count": n} for i, n in top.most_common(15)]
    stats["window_days"] = int(config.output["stats_window_days"])
    stats["updated"] = iso(now)
    write_json(path, stats, compact=True)
    return stats


def list_days(docs_dir: Path) -> list[tuple[str, Path]]:
    root = docs_dir / "data" / "findings"
    out = []
    for path in root.glob("*/*/*.json"):
        day = "-".join((path.parent.parent.name, path.parent.name, path.stem))
        if parse_ts(day + "T00:00:00Z"):
            out.append((day, path))
    return sorted(out)


def prune_shards(docs_dir: Path, now: datetime, config: Config) -> int:
    """Delete daily files older than the retention window. Returns how many were removed."""
    floor = (now - timedelta(days=int(config.output["retention_days"]))).strftime("%Y-%m-%d")
    removed = 0
    for day, path in list_days(docs_dir):
        if day < floor:
            path.unlink()
            removed += 1
            for folder in (path.parent, path.parent.parent):
                if not any(folder.iterdir()):
                    folder.rmdir()
    return removed


def write_index(docs_dir: Path) -> dict[str, int]:
    """``findings/index.json``: every available day and how many findings it holds."""
    days = {}
    for day, path in list_days(docs_dir):
        days[day] = len((read_json(path, {}) or {}).get("findings", []))
    write_json(docs_dir / "data" / "findings" / "index.json", {"days": days}, compact=True)
    return days


def live_high_keys(docs_dir: Path) -> set[str]:
    """Keys of every retained high-severity finding (used to prune report files)."""
    keys = set()
    for _, path in list_days(docs_dir):
        for record in (read_json(path, {}) or {}).get("findings", []):
            if record.get("severity") == "high":
                keys.add(record["key"])
    return keys


def write_health(docs_dir: Path, now: datetime, counts: RunCounts, duration: float) -> None:
    """Written only after a successful run; the dashboard shows its age."""
    write_json(
        docs_dir / "data" / "health.json",
        {
            "status": "ok",
            "last_success": iso(now),
            "duration_seconds": round(duration, 1),
            "scanned": sum(counts.scanned.values()),
            "flagged": sum(counts.flagged.values()),
            "package_errors": len(counts.errors),
            "skipped": dict(sorted(counts.skipped.items())),
            "warnings": counts.warnings[:10],
        },
    )
