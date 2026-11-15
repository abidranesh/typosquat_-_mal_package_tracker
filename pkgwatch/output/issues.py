"""Triage issues: one GitHub issue per new high finding, labelled ``needs-triage``.

Issues are opened in this project's own repository so a human can review the finding.
Nothing is ever reported to npm or PyPI automatically.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..config import Config
from ..http import Client, HttpError
from .reports import render_report, report_path

API = "https://api.github.com"
LABEL = "needs-triage"
HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
_MAX_BODY = 60_000


def marker(record: dict[str, Any]) -> str:
    """The de-duplication key that appears in every issue title."""
    return f"{record['ecosystem']}/{record['name']}@{record['version']}"


def issue_title(record: dict[str, Any]) -> str:
    return f"[PkgWatch] Suspicious package: {marker(record)}"


def ensure_label(client: Client, config: Config) -> None:
    """Create the triage label; an "already exists" response (422) is fine."""
    try:
        client.request(
            "POST",
            f"{API}/repos/{config.repo}/labels",
            headers=HEADERS,
            json_body={
                "name": LABEL,
                "color": "d93f0b",
                "description": "PkgWatch finding awaiting human review",
            },
            github=True,
        )
    except HttpError as exc:
        if exc.status != 422:
            raise


def issue_exists(client: Client, config: Config, record: dict[str, Any]) -> bool:
    query = f'repo:{config.repo} is:issue in:title "{marker(record)}"'
    doc = client.get_json(
        f"{API}/search/issues?q={quote(query, safe='')}&per_page=20", headers=HEADERS, github=True
    )
    wanted = issue_title(record)
    return any(item.get("title") == wanted for item in doc.get("items", []))


def create_issue(client: Client, config: Config, record: dict[str, Any], body: str) -> str:
    resp = client.request(
        "POST",
        f"{API}/repos/{config.repo}/issues",
        headers=HEADERS,
        json_body={"title": issue_title(record), "body": body[:_MAX_BODY], "labels": [LABEL]},
        github=True,
    )
    return str(resp.json().get("html_url", ""))


def open_issues(
    client: Client,
    config: Config,
    records: list[dict[str, Any]],
    reports_dir: Path,
) -> tuple[list[str], list[str], list[str]]:
    """Open issues for high records.

    Returns ``(created issue URLs, keys left for the next run, warnings)``. API failures
    stop the batch and push the remaining keys to the backlog instead of raising, so a
    GitHub hiccup never loses scan results.
    """
    high = [r for r in records if r.get("severity") == "high"]
    limit = int(config.limits["max_issues_per_run"])
    batch, backlog = high[:limit], [r["key"] for r in high[limit:]]
    created: list[str] = []
    warnings: list[str] = []
    if not batch:
        return created, backlog, warnings
    try:
        ensure_label(client, config)
    except HttpError as exc:
        warnings.append(f"could not ensure the {LABEL} label: {exc}")
    for index, record in enumerate(batch):
        try:
            if issue_exists(client, config, record):
                continue
            path = report_path(reports_dir, record)
            body = (
                path.read_text(encoding="utf-8") if path.exists() else render_report(record, config)
            )
            created.append(create_issue(client, config, record, body))
        except HttpError as exc:
            warnings.append(f"issue creation stopped at {record['key']}: {exc}")
            backlog = [r["key"] for r in batch[index:]] + backlog
            break
    return created, backlog, warnings
