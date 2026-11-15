"""Ready-to-send report text for high-score findings.

Reports are written to ``reports/<ecosystem>/<name>-<version>.md`` and attached to a
triage issue. PkgWatch never submits anything to npm or PyPI itself: a human reviews
the report and decides whether to forward it.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from ..config import Config
from .json_out import registry_url

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
UPSTREAM = {
    "npm": 'https://www.npmjs.com/support (choose "Report malware"), or the '
    '"Report malware" link on the package page',
    "pypi": 'the "Report project as malware" link on the project page, or security@pypi.org',
}


def safe_text(text: str) -> str:
    """Neutralise @mentions so a scoped package name never pings a GitHub account."""
    return text.replace("@", "@<!-- -->")


def fence(text: str) -> str:
    """A code fence longer than any backtick run inside ``text``."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}text\n{text}\n{ticks}"


def false_positive_url(config: Config, record: dict[str, Any]) -> str:
    """Prefilled GitHub issue for reporting a false positive."""
    label = f"{record['ecosystem']}/{record['name']}@{record['version']}"
    query = urlencode(
        {
            "template": "false-positive.yml",
            "labels": "false-positive",
            "title": f"False positive: {label}",
            "package": label,
        },
        quote_via=quote,
    )
    return f"https://github.com/{config.repo}/issues/new?{query}"


def _slug(text: str, limit: int) -> str:
    """Filesystem-safe and bounded; long values keep a hash so they stay unique."""
    slug = re.sub(r"\.{2,}", ".", _UNSAFE.sub("_", text)).strip("._") or "_"
    if len(slug) > limit:
        digest = hashlib.sha1(text.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]
        slug = f"{slug[: limit - 9]}-{digest}"
    return slug


def report_path(reports_dir: Path, record: dict[str, Any]) -> Path:
    name = _slug(record["name"].lstrip("@").replace("/", "__"), 80)
    version = _slug(record["version"], 40)
    return reports_dir / record["ecosystem"] / f"{name}-{version}.md"


def render_report(record: dict[str, Any], config: Config) -> str:
    eco, name, version = record["ecosystem"], record["name"], record["version"]
    lines = [
        f"# Suspicious package report: `{name}` {version} ({eco})",
        "",
        "> Generated automatically by PkgWatch from static analysis. The package was "
        "**not** installed or executed. This is a lead for human review, not a verdict: "
        "false positives happen.",
        "",
        "| | |",
        "|---|---|",
        f"| Package | `{name}` |",
        f"| Version | `{version}` |",
        f"| Ecosystem | {eco} |",
        f"| Risk score | {record['score']} / 100 ({record['severity']}) |",
        f"| Published | {record.get('published_at') or 'unknown'} |",
        f"| Scanned | {record['scanned_at']} |",
        f"| Registry page | {registry_url(eco, name, version)} |",
    ]
    if record.get("targets"):
        targets = ", ".join(f"`{t}`" for t in record["targets"])
        lines.append(f"| Possibly imitating | {targets} |")
    lines += ["", "## Indicators", ""]
    for finding in record["findings"]:
        lines.append(
            f"- **{finding['id']}** ({finding['severity']}, +{finding['weight']}): "
            f"{safe_text(finding['message'])}"
        )
        evidence = finding.get("evidence")
        if evidence:
            lines += ["", f"  Evidence in `{evidence['path']}`:", ""]
            lines += ["  " + row for row in fence(evidence["snippet"]).splitlines()]
            lines.append("")
    lines += [
        "",
        "## Suggested text for an upstream report",
        "",
        f"The {eco} package `{name}` version `{version}` shows indicators consistent with a "
        "supply-chain attack. Static analysis (no execution) found:",
        "",
    ]
    lines += [f"- {safe_text(f['message'])}" for f in record["findings"]]
    lines += [
        "",
        "Please review the package and remove it if it violates registry policy.",
        "",
        "## Before forwarding",
        "",
        "1. Open the registry page and read the flagged files yourself.",
        "2. Confirm the behaviour is not a legitimate feature of the package.",
        f"3. If it holds up, report it via {UPSTREAM.get(eco, 'the registry')}.",
        f"4. If it does not, record it here: {false_positive_url(config, record)}",
        "",
    ]
    return "\n".join(lines)


def write_reports(reports_dir: Path, records: list[dict[str, Any]], config: Config) -> list[Path]:
    """Write one report per high-severity record. Returns the paths written."""
    written = []
    for record in records:
        if record.get("severity") != "high":
            continue
        path = report_path(reports_dir, record)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(render_report(record, config), encoding="utf-8", newline="\n")
        except OSError:
            continue  # e.g. path too long on Windows; the issue body is rendered on demand
        written.append(path)
    return written


def prune_reports(reports_dir: Path, live: list[dict[str, Any]]) -> int:
    """Remove report files whose finding has aged out of the retained data."""
    keep = {report_path(reports_dir, record) for record in live}
    removed = 0
    for path in reports_dir.glob("*/*.md"):
        if path not in keep:
            path.unlink()
            removed += 1
    return removed
