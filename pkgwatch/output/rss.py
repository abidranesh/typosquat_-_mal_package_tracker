"""RSS 2.0 feeds: ``feed.xml`` (everything listed) and ``feed-high.xml`` (high only)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from email.utils import format_datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..config import Config
from ..util import parse_ts
from .reports import false_positive_url


def detail_url(config: Config, record: dict[str, Any]) -> str:
    """Dashboard deep link for one finding (hash routing)."""
    name = quote(record["name"], safe="@/")
    version = quote(record["version"], safe="")
    return f"{config.project['site_url']}#/{record['ecosystem']}/{name}/{version}"


def _rfc822(stamp: str | None) -> str | None:
    moment = parse_ts(stamp)
    return format_datetime(moment, usegmt=True) if moment else None


def build_feed(records: list[dict[str, Any]], config: Config, *, high_only: bool = False) -> bytes:
    name = config.project["name"]
    items = [r for r in records if not high_only or r.get("severity") == "high"]
    items = items[: int(config.output["feed_items"])]
    rss = ET.Element("rss", version="2.0")
    channel = ET.SubElement(rss, "channel")
    suffix = "high-risk suspicious packages" if high_only else "suspicious packages"
    ET.SubElement(channel, "title").text = f"{name}: {suffix} on npm and PyPI"
    ET.SubElement(channel, "link").text = config.project["site_url"]
    ET.SubElement(channel, "description").text = (
        f"{name} statically analyses newly published npm and PyPI packages and lists the "
        "ones that look suspicious. Entries are leads for human review, not verdicts."
    )
    ET.SubElement(channel, "language").text = "en"
    if items and (built := _rfc822(items[0]["scanned_at"])):
        ET.SubElement(channel, "lastBuildDate").text = built
    for record in items:
        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = (
            f"[{record['severity'].upper()} {record['score']}] suspicious {record['ecosystem']} "
            f"package: {record['name']} {record['version']}"
        )
        ET.SubElement(item, "link").text = detail_url(config, record)
        ET.SubElement(item, "guid", isPermaLink="false").text = f"pkgwatch:{record['key']}"
        if published := _rfc822(record["scanned_at"]):
            ET.SubElement(item, "pubDate").text = published
        for finding in record["findings"]:
            ET.SubElement(item, "category").text = finding["id"]
        reasons = "".join(f"<li>{_escape(f['message'])}</li>" for f in record["findings"])
        ET.SubElement(item, "description").text = (
            f"<p>Risk score {record['score']}/100 ({record['severity']}).</p><ul>{reasons}</ul>"
            f'<p><a href="{_escape(record["registry_url"])}">Registry page</a> · '
            f'<a href="{_escape(false_positive_url(config, record))}">Report a false positive'
            "</a></p>"
        )
    ET.indent(rss)
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(rss, encoding="utf-8") + b"\n"


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def write_feeds(docs_dir: Path, records: list[dict[str, Any]], config: Config) -> None:
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "feed.xml").write_bytes(build_feed(records, config))
    (docs_dir / "feed-high.xml").write_bytes(build_feed(records, config, high_only=True))
