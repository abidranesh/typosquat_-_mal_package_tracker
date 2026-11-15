"""Scan entrypoint: ``python -m pkgwatch.scan``.

One run reads everything published since the stored cursors (capped per run), scores
each package statically, and rewrites the public data under ``docs/``. Packages are
never installed, imported or executed.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import threading
import time
import xmlrpc.client
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.parsers.expat import ExpatError

from .baseline import Baseline, load_baseline
from .config import Config, load_config
from .http import Client, HttpError, TooLarge
from .output import issues, json_out, reports, rss
from .output.json_out import RunCounts
from .scoring import analyze
from .sources import npm, pypi
from .state import DEFAULT_PATH as STATE_PATH
from .state import empty_state, load_state, save_state
from .util import utcnow

ROOT = Path(__file__).resolve().parent.parent
RECENT_MAX = 6000
COLD_START_MAX = 300
NPM_MAX_BACKLOG = 400_000  # sequence numbers; beyond this the scanner skips ahead
PYPI_MAX_BACKLOG = 60_000  # serials
ERROR_RATE_LIMIT = 0.3


@dataclass(frozen=True)
class Job:
    ecosystem: str
    name: str
    version: str | None
    cursor: int | None


@dataclass
class Outcome:
    record: dict[str, Any] | None = None
    ecosystem: str = ""
    scanned: bool = False
    skipped: str | None = None
    error: str | None = None
    detector_errors: list[str] = field(default_factory=list)


def short_hash(key: str) -> str:
    return hashlib.sha1(key.encode("utf-8"), usedforsecurity=False).hexdigest()[:10]


class Recent:
    """Thread-safe set of recently scanned package versions (stored as short hashes)."""

    def __init__(self, hashes: list[str] | None = None):
        self._order = list(hashes or [])
        self._seen = set(self._order)
        self._lock = threading.Lock()

    def claim(self, key: str) -> bool:
        """True if ``key`` is new (and now recorded); False if it was already scanned."""
        digest = short_hash(key)
        with self._lock:
            if digest in self._seen:
                return False
            self._seen.add(digest)
            self._order.append(digest)
            return True

    def dump(self) -> list[str]:
        return self._order[-RECENT_MAX:]


class Scanner:
    def __init__(
        self,
        client: Client,
        config: Config,
        baselines: dict[str, Baseline],
        recent: Recent,
        now: datetime,
    ):
        self.client = client
        self.config = config
        self.baselines = baselines
        self.recent = recent
        self.now = now

    def scan(self, job: Job) -> Outcome:
        outcome = Outcome(ecosystem=job.ecosystem)
        try:
            ctx = self._context(job, outcome)
            if ctx is None:
                return outcome
            result = analyze(ctx)
            outcome.scanned = True
            outcome.detector_errors = [f"{ctx.key}: {e}" for e in result.errors]
            if result.listed:
                outcome.record = json_out.make_record(ctx, result, self.now)
        except TooLarge:
            outcome.skipped = "metadata-too-large"
        except HttpError as exc:
            outcome.error = f"{job.ecosystem}/{job.name}: {exc}"
        except Exception as exc:  # noqa: BLE001 - one hostile package must not end the run
            outcome.error = f"{job.ecosystem}/{job.name}: {type(exc).__name__}: {exc}"
        return outcome

    def _context(self, job: Job, outcome: Outcome):
        if job.ecosystem == "npm":
            packument = npm.fetch_packument(self.client, job.name)
            if packument is None:
                outcome.skipped = "gone"
                return None
            hours = float(self.config.limits["npm_recent_hours"])
            version = npm.select_version(packument, self.now, hours)
            if version is None:
                outcome.skipped = "no-recent-version"
                return None
            if not self.recent.claim(f"npm/{job.name}/{version}"):
                outcome.skipped = "already-scanned"
                return None
            return npm.build_context(
                self.client, packument, version, self.config, self.baselines["npm"], self.now
            )
        project = pypi.fetch_release(self.client, job.name, job.version)
        if project is None:
            outcome.skipped = "gone"
            return None
        version = job.version or pypi.newest_version(project)
        if version is None:
            outcome.skipped = "no-files"
            return None
        if not self.recent.claim(f"pypi/{job.name}/{version}"):
            outcome.skipped = "already-scanned"
            return None
        ctx = pypi.build_context(
            self.client, project, version, self.config, self.baselines["pypi"], self.now
        )
        if ctx is None:
            outcome.skipped = "no-files"
        return ctx


def plan_npm(
    client: Client, seq: int | None, limit: int, counts: RunCounts
) -> tuple[list[Job], int | None]:
    """Jobs for npm and the cursor to store if every job completes."""
    if seq is None:
        changes = npm.latest_changes(client, min(limit, COLD_START_MAX))
        final = max((c.seq for c in changes), default=None)
    else:
        head = npm.current_seq(client)
        if head - seq > NPM_MAX_BACKLOG:
            counts.warnings.append(
                f"npm backlog of {head - seq} sequences exceeded the limit; skipped ahead"
            )
            seq = head - NPM_MAX_BACKLOG
        changes, final = npm.fetch_changes(client, seq, limit)
    latest: dict[str, npm.Change] = {}
    for change in changes:
        latest[change.name] = change
    jobs = [
        Job("npm", c.name, None, c.seq)
        for c in sorted(latest.values(), key=lambda c: c.seq)
        if not c.deleted
    ]
    return jobs, final


def _pypi_rss_jobs(client: Client, etags: dict[str, str], limit: int) -> list[Job]:
    seen: dict[tuple[str, str | None], Job] = {}
    for url in (pypi.RSS_UPDATES, pypi.RSS_NEW):
        items, etag = pypi.fetch_rss(client, url, etags.get(url))
        if etag:
            etags[url] = etag
        for item in items:
            seen.setdefault(
                (item.name.lower(), item.version), Job("pypi", item.name, item.version, None)
            )
    return list(seen.values())[:limit]


def plan_pypi(
    client: Client, state: dict[str, Any], limit: int, counts: RunCounts
) -> tuple[list[Job], int | None]:
    """Jobs for PyPI and the serial to store if every job completes.

    The changelog-by-serial API gives gap-free coverage. The RSS feeds only hold the
    last ~100 releases, so they serve as the cold start and as the fallback.
    """
    serial = state.get("serial")
    etags = state.setdefault("etags", {})
    try:
        head = pypi.last_serial(client)
    except (HttpError, xmlrpc.client.Error, ExpatError, ValueError, TypeError) as exc:
        counts.warnings.append(f"PyPI changelog API unavailable ({exc}); used RSS feeds instead")
        return _pypi_rss_jobs(client, etags, limit), serial
    if serial is None:
        return _pypi_rss_jobs(client, etags, min(limit, COLD_START_MAX)), head
    if head - serial > PYPI_MAX_BACKLOG:
        counts.warnings.append(
            f"PyPI backlog of {head - serial} serials exceeded the limit; skipped ahead"
        )
        serial = head - PYPI_MAX_BACKLOG
    try:
        releases, newest = pypi.changelog_since(client, serial)
    except (HttpError, xmlrpc.client.Error, ExpatError, ValueError, TypeError, IndexError) as exc:
        counts.warnings.append(f"PyPI changelog API failed ({exc}); used RSS feeds instead")
        return _pypi_rss_jobs(client, etags, limit), head
    jobs = [Job("pypi", r.name, r.version, r.serial) for r in releases]
    if len(jobs) > limit:
        return jobs[:limit], None  # cursor comes from the last job that completes
    return jobs, max(newest, serial)


def run_jobs(
    scanner: Scanner,
    jobs: list[Job],
    counts: RunCounts,
    deadline: float,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[list[dict[str, Any]], int]:
    """Scan jobs in order with bounded concurrency. Returns (records, jobs completed)."""
    records: list[dict[str, Any]] = []
    workers = int(scanner.config.limits["concurrency"])
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for start in range(0, len(jobs), workers * 4):
            if clock() > deadline:
                counts.warnings.append(
                    f"time budget reached; {len(jobs) - done} package(s) carried over"
                )
                break
            chunk = jobs[start : start + workers * 4]
            for outcome in pool.map(scanner.scan, chunk):
                if outcome.error:
                    counts.errors.append(outcome.error)
                elif outcome.skipped:
                    counts.skipped[outcome.skipped] += 1
                elif outcome.scanned:
                    counts.scanned[outcome.ecosystem] += 1
                counts.errors.extend(outcome.detector_errors)
                if outcome.record:
                    records.append(outcome.record)
            done += len(chunk)
    return records, done


def _cursor_after(jobs: list[Job], done: int, final: int | None, previous: int | None):
    if done >= len(jobs) and final is not None:
        return final
    completed = [j.cursor for j in jobs[:done] if j.cursor is not None]
    return completed[-1] if completed else previous


def write_outputs(
    docs_dir: Path,
    reports_dir: Path,
    records: list[dict[str, Any]],
    counts: RunCounts,
    now: datetime,
    config: Config,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Write every public artefact. Returns (records that were new, latest list)."""
    fresh = json_out.merge_shards(docs_dir, records)
    for record in fresh:
        counts.flagged[record["ecosystem"]] += 1
        if record["severity"] == "high":
            counts.high[record["ecosystem"]] += 1
        for finding_id in {f["id"] for f in record["findings"]}:
            counts.detectors[finding_id] += 1
    latest = json_out.update_latest(docs_dir, records, config)
    json_out.update_stats(docs_dir, counts, now, config)
    json_out.prune_shards(docs_dir, now, config)
    json_out.write_index(docs_dir)
    rss.write_feeds(docs_dir, latest, config)
    reports.write_reports(reports_dir, fresh, config)
    live = json_out.live_high_keys(docs_dir)
    keep = [{"ecosystem": k.split("/", 1)[0], **_split_key(k)} for k in live]
    reports.prune_reports(reports_dir, keep)
    return fresh, latest


def _split_key(key: str) -> dict[str, str]:
    _, rest = key.split("/", 1)
    name, version = rest.rsplit("/", 1)
    return {"name": name, "version": version}


def summarize(counts: RunCounts, fresh: list[dict[str, Any]], duration: float) -> str:
    lines = [
        f"PkgWatch scan finished in {duration:.0f}s",
        f"  scanned: {dict(counts.scanned)} (total {sum(counts.scanned.values())})",
        f"  newly flagged: {dict(counts.flagged)}, high: {dict(counts.high)}",
        f"  skipped: {dict(counts.skipped)}",
        f"  package errors: {len(counts.errors)}",
    ]
    lines += [f"  warning: {w}" for w in counts.warnings]
    lines += [f"  error: {e}" for e in counts.errors[:10]]
    for record in sorted(fresh, key=lambda r: -r["score"])[:25]:
        ids = ", ".join(sorted({f["id"] for f in record["findings"]}))
        lines.append(
            f"  [{record['severity']:6} {record['score']:3d}] {record['ecosystem']}/"
            f"{record['name']}@{record['version']}: {ids}"
        )
    return "\n".join(lines)


def run(
    args: argparse.Namespace, client: Client | None = None, config: Config | None = None
) -> int:
    config = config or load_config()
    started = time.monotonic()
    now = utcnow()
    counts = RunCounts()
    dry = bool(args.dry_run)
    docs_dir = Path(args.output_dir or (ROOT / "dry-run-out" if dry else ROOT / "docs"))
    reports_dir = Path(
        args.reports_dir or (docs_dir.parent / "reports" if not dry else docs_dir / "reports")
    )
    state_path = Path(args.state or STATE_PATH)
    state = empty_state() if dry else load_state(state_path)
    limit = int(args.limit or config.limits["max_packages_per_run"])
    ecosystems = ["npm", "pypi"] if args.ecosystem == "all" else [args.ecosystem]
    per_eco = max(1, limit // len(ecosystems))
    deadline = started + float(config.limits["run_deadline_seconds"])
    baselines = {eco: load_baseline(eco, args.baselines) for eco in ("npm", "pypi")}
    recent = Recent(state.get("recent"))
    fatal: list[str] = []
    records: list[dict[str, Any]] = []
    total_jobs = 0
    owns_client = client is None
    client = client or Client(config, token=os.environ.get("GITHUB_TOKEN"))
    try:
        scanner = Scanner(client, config, baselines, recent, now)
        for eco in ecosystems:
            try:
                if eco == "npm":
                    jobs, final = plan_npm(client, state["npm"].get("seq"), per_eco, counts)
                else:
                    jobs, final = plan_pypi(client, state["pypi"], per_eco, counts)
            except (HttpError, ValueError, KeyError, TypeError) as exc:
                fatal.append(f"{eco} source failed: {type(exc).__name__}: {exc}")
                continue
            total_jobs += len(jobs)
            found, done = run_jobs(scanner, jobs, counts, deadline)
            records.extend(found)
            field_name = "seq" if eco == "npm" else "serial"
            state[eco][field_name] = _cursor_after(jobs, done, final, state[eco].get(field_name))

        fresh, latest = write_outputs(docs_dir, reports_dir, records, counts, now, config)

        if not dry and not args.no_issues and os.environ.get("GITHUB_TOKEN"):
            by_key = {r["key"]: r for r in latest}
            pending = [by_key[k] for k in state.get("issue_backlog", []) if k in by_key]
            created, backlog, warnings = issues.open_issues(
                client, config, pending + fresh, reports_dir
            )
            counts.warnings.extend(warnings)
            state["issue_backlog"] = backlog[:200]
            if created:
                print(f"opened {len(created)} triage issue(s)")
    finally:
        if owns_client:
            client.close()

    duration = time.monotonic() - started
    too_many_errors = len(counts.errors) > max(10, ERROR_RATE_LIMIT * total_jobs)
    if too_many_errors:
        fatal.append(f"{len(counts.errors)} of {total_jobs} packages failed")
    if not fatal:
        json_out.write_health(docs_dir, now, counts, duration)
    if not dry:
        state["recent"] = recent.dump()
        save_state(state, state_path)

    summary = summarize(counts, fresh, duration)
    print(summary)
    for message in fatal:
        print(f"FATAL: {message}", file=sys.stderr)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write("```\n" + summary + "\n" + "\n".join(f"FATAL: {m}" for m in fatal) + "\n```\n")
    return 1 if fatal else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pkgwatch.scan", description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="ignore and do not save cursors, open no issues, write to ./dry-run-out",
    )
    parser.add_argument("--limit", type=int, help="maximum packages to process this run")
    parser.add_argument("--ecosystem", choices=("all", "npm", "pypi"), default="all")
    parser.add_argument("--output-dir", help="where data/ and the feeds are written")
    parser.add_argument("--reports-dir", help="where report text files are written")
    parser.add_argument("--state", help="path to cursors.json")
    parser.add_argument("--baselines", help="directory holding the baseline snapshots")
    parser.add_argument("--no-issues", action="store_true", help="never open GitHub issues")
    return parser


def main(argv: list[str] | None = None) -> int:
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
