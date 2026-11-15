"""PyPI source: RSS feeds, the changelog-by-serial API and the JSON API."""

from __future__ import annotations

import contextlib
import xml.etree.ElementTree as ET
import xmlrpc.client
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import quote, urlsplit

from ..baseline import Baseline
from ..config import Config
from ..context import PackageContext
from ..http import Client, NotFound
from ..util import parse_ts
from .common import clean_repo_url, host_allowed, is_repo_host, load_archive

RSS_NEW = "https://pypi.org/rss/packages.xml"
RSS_UPDATES = "https://pypi.org/rss/updates.xml"
XMLRPC_URL = "https://pypi.org/pypi"
JSON_URL = "https://pypi.org/pypi/{name}/json"
VERSION_URL = "https://pypi.org/pypi/{name}/{version}/json"
FILE_HOSTS = ("files.pythonhosted.org",)
NEW_PACKAGE_DAYS = 30
_MAX_XML = 8 * 1024 * 1024


@dataclass(frozen=True)
class Release:
    name: str
    version: str | None  # None: "newest release of this project" (from packages.xml)
    published: datetime | None = None
    serial: int | None = None


def parse_rss(xml: bytes) -> list[Release]:
    """Parse ``packages.xml`` or ``updates.xml``. Malformed items are skipped."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    out = []
    for item in root.iter("item"):
        link = (item.findtext("link") or "").strip()
        parts = [p for p in urlsplit(link).path.split("/") if p]
        if len(parts) < 2 or parts[0] != "project":
            continue
        published = None
        with contextlib.suppress(TypeError, ValueError):
            published = parsedate_to_datetime(item.findtext("pubDate") or "")
        out.append(Release(parts[1], parts[2] if len(parts) > 2 else None, published))
    return out


def fetch_rss(client: Client, url: str, etag: str | None) -> tuple[list[Release], str | None]:
    """Conditional fetch of a feed. Returns (items, new etag); a 304 yields no items."""
    resp = client.get_conditional(url, etag, max_bytes=_MAX_XML)
    if resp.status == 304:
        return [], etag
    return parse_rss(resp.body), resp.etag or etag


def _xmlrpc(client: Client, method: str, *params: Any) -> Any:
    body = xmlrpc.client.dumps(params, method).encode()
    resp = client.request(
        "POST",
        XMLRPC_URL,
        content=body,
        headers={"Content-Type": "text/xml"},
        max_bytes=_MAX_XML * 4,
    )
    values, _ = xmlrpc.client.loads(resp.body)
    return values[0]


def last_serial(client: Client) -> int:
    return int(_xmlrpc(client, "changelog_last_serial"))


def changelog_since(client: Client, serial: int) -> tuple[list[Release], int]:
    """New files and releases since ``serial`` (oldest first), and the newest serial seen."""
    rows = _xmlrpc(client, "changelog_since_serial", int(serial))
    out: list[Release] = []
    seen: set[tuple[str, str]] = set()
    newest = int(serial)
    for row in rows:
        name, version, stamp, action, row_serial = row[0], row[1], row[2], row[3], int(row[4])
        newest = max(newest, row_serial)
        if not version or not str(action).startswith(("add ", "new release")):
            continue
        key = (str(name), str(version))
        if key in seen:
            continue
        seen.add(key)
        published = datetime.fromtimestamp(int(stamp), tz=UTC)
        out.append(Release(key[0], key[1], published, row_serial))
    return out, newest


def fetch_project(client: Client, name: str) -> dict[str, Any] | None:
    try:
        doc = client.get_json(JSON_URL.format(name=quote(name, safe="")))
    except NotFound:
        return None
    return doc if isinstance(doc, dict) else None


def fetch_release(client: Client, name: str, version: str | None) -> dict[str, Any] | None:
    """Project metadata guaranteed to include ``version`` when that release exists.

    The project document is CDN-cached and can lag a new release by minutes, so when the
    wanted version is missing its own document is fetched and merged in.
    """
    project = fetch_project(client, name)
    if project is None or version is None or (project.get("releases") or {}).get(version):
        return project
    url = VERSION_URL.format(name=quote(name, safe=""), version=quote(version, safe=""))
    try:
        doc = client.get_json(url)
    except NotFound:
        return project
    if isinstance(doc, dict) and doc.get("urls"):
        project.setdefault("releases", {})[version] = doc["urls"]
        project["info"] = doc.get("info") or project.get("info")
    return project


def _upload_time(files: list[dict[str, Any]]) -> datetime | None:
    stamps = [parse_ts(f.get("upload_time_iso_8601")) for f in files]
    stamps = [s for s in stamps if s]
    return min(stamps) if stamps else None


def _release_times(project: dict[str, Any]) -> list[tuple[datetime, str]]:
    out = []
    for version, files in (project.get("releases") or {}).items():
        moment = _upload_time(files or [])
        if moment:
            out.append((moment, version))
    return sorted(out)


def newest_version(project: dict[str, Any]) -> str | None:
    ordered = _release_times(project)
    return ordered[-1][1] if ordered else None


def _repo_url(info: dict[str, Any]) -> str | None:
    urls = info.get("project_urls") or {}
    preferred = ("source", "repository", "code", "github", "source code", "homepage", "home")
    ranked = sorted(
        urls.items(),
        key=lambda kv: preferred.index(kv[0].lower()) if kv[0].lower() in preferred else 99,
    )
    for _, value in [*ranked, ("home_page", info.get("home_page"))]:
        url = clean_repo_url(value)
        if is_repo_host(url):
            return "/".join(url.split("/")[:5])
    return None


def _wheel_kind(filename: str) -> str:
    return "wheel:pure" if filename.endswith("-none-any.whl") else "wheel:platform"


def _pick_files(files: list[dict[str, Any]], budget: int) -> list[dict[str, Any]]:
    """At most one sdist and one wheel (pure-Python preferred) within the byte budget."""
    usable = [
        f
        for f in files
        if isinstance(f.get("url"), str)
        and host_allowed(f["url"], FILE_HOSTS)
        and isinstance(f.get("size"), int)
    ]
    sdists = [f for f in usable if f.get("packagetype") == "sdist"]
    wheels = sorted(
        (f for f in usable if f.get("packagetype") == "bdist_wheel"),
        key=lambda f: (_wheel_kind(f["filename"]) != "wheel:pure", f["size"]),
    )
    picked = []
    for group in (sdists, wheels):
        for candidate in group:
            if candidate["size"] <= budget:
                picked.append(candidate)
                budget -= candidate["size"]
                break
    return picked


def build_context(
    client: Client,
    project: dict[str, Any],
    version: str,
    config: Config,
    baseline: Baseline,
    now: datetime,
    *,
    fetch_archive: bool = True,
) -> PackageContext | None:
    """Assemble a ``PackageContext`` for ``version`` (None if it has no files)."""
    releases = project.get("releases") or {}
    files = releases.get(version) or []
    if not files:
        return None
    info = project.get("info") or {}
    ordered = _release_times(project)
    earlier = [v for _, v in ordered if v != version]
    previous = earlier[-1] if earlier else None
    summary = info.get("summary") if info.get("version") == version else None
    owners = [
        r.get("user")
        for r in (project.get("ownership") or {}).get("roles", [])
        if isinstance(r, dict) and isinstance(r.get("user"), str)
    ]
    created = ordered[0][0] if ordered else None
    ctx = PackageContext(
        ecosystem="pypi",
        name=str(info.get("name") or ""),
        version=version,
        config=config,
        baseline=baseline,
        description=summary if summary is not None else info.get("summary"),
        readme=info.get("description"),
        repository_url=_repo_url(info),
        homepage=info.get("home_page") or None,
        maintainers=owners,
        published_at=_upload_time(files),
        package_created_at=created,
        publisher_is_new=(now - created <= timedelta(days=NEW_PACKAGE_DAYS)) if created else None,
        version_count=len(ordered),
        previous_version=previous,
        size=max(f.get("size") or 0 for f in files),
        previous_size=max((f.get("size") or 0 for f in releases.get(previous) or []), default=None)
        if previous
        else None,
    )
    budget = int(config.limits["max_download_bytes"])
    picked = _pick_files(files, budget)
    if not picked:
        ctx.archive_error = "skipped: no downloadable file within the size limit"
    for chosen in picked:
        filename = str(chosen["filename"])
        kind = "sdist" if chosen.get("packagetype") == "sdist" else _wheel_kind(filename)
        ctx.archive_kinds.append(kind)
        if fetch_archive:
            load_archive(client, ctx, chosen["url"], filename, budget)
    return ctx
