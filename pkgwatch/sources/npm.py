"""npm source: the replication changes feed plus packuments from the registry."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

from ..baseline import Baseline
from ..config import Config
from ..context import PackageContext
from ..detectors.names import best_match
from ..http import Client, HttpError, NotFound
from ..util import parse_ts
from .common import clean_repo_url, host_allowed, load_archive

REPLICATE_ROOT = "https://replicate.npmjs.com/"
CHANGES_URL = "https://replicate.npmjs.com/registry/_changes"
REGISTRY = "https://registry.npmjs.org"
SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
TARBALL_HOSTS = ("registry.npmjs.org",)
NEW_PACKAGE_DAYS = 30
NEW_PUBLISHER_MAX_PACKAGES = 2


@dataclass(frozen=True)
class Change:
    seq: int
    name: str
    deleted: bool = False


def _parse_changes(doc: dict[str, Any]) -> list[Change]:
    out = []
    for row in doc.get("results", []):
        name = row.get("id")
        if not isinstance(name, str) or name.startswith("_design/"):
            continue
        out.append(Change(int(row["seq"]), name, bool(row.get("deleted"))))
    return out


def current_seq(client: Client) -> int:
    return int(client.get_json(REPLICATE_ROOT)["update_seq"])


def fetch_changes(client: Client, since: int, limit: int) -> tuple[list[Change], int]:
    """Changes after ``since`` in ascending order, and the sequence to resume from."""
    doc = client.get_json(f"{CHANGES_URL}?since={int(since)}&limit={int(limit)}")
    changes = _parse_changes(doc)
    last = int(doc.get("last_seq", since))
    return changes, max([last, *(c.seq for c in changes)]) if changes else last


def latest_changes(client: Client, limit: int) -> list[Change]:
    """Cold start: the most recent ``limit`` changes, oldest first."""
    doc = client.get_json(f"{CHANGES_URL}?descending=true&limit={int(limit)}")
    return sorted(_parse_changes(doc), key=lambda c: c.seq)


def packument_url(name: str) -> str:
    return f"{REGISTRY}/{quote(name, safe='@')}"


def fetch_packument(client: Client, name: str) -> dict[str, Any] | None:
    try:
        doc = client.get_json(packument_url(name))
    except NotFound:
        return None
    return doc if isinstance(doc, dict) else None


def publisher_package_count(client: Client, user: str) -> int | None:
    """How many packages a maintainer has, via the public search API (None if unknown)."""
    try:
        doc = client.get_json(f"{SEARCH_URL}?text=maintainer:{quote(user, safe='')}&size=1")
        return int(doc["total"])
    except (HttpError, KeyError, TypeError, ValueError):
        return None


def _names(entries: Any) -> list[str]:
    out = []
    for entry in entries if isinstance(entries, list) else []:
        name = entry.get("name") if isinstance(entry, dict) else entry
        if isinstance(name, str) and name:
            out.append(name)
    return out


def _times(packument: dict[str, Any]) -> list[tuple[datetime, str]]:
    versions = packument.get("versions") or {}
    out = []
    for version, stamp in (packument.get("time") or {}).items():
        moment = parse_ts(stamp)
        if version in versions and moment:
            out.append((moment, version))
    return sorted(out)


def select_version(packument: dict[str, Any], now: datetime, recent_hours: float) -> str | None:
    """The newest published version, if it was published within ``recent_hours``."""
    ordered = _times(packument)
    if not ordered:
        return None
    moment, version = ordered[-1]
    if now - moment > timedelta(hours=recent_hours):
        return None
    return version


def build_context(
    client: Client,
    packument: dict[str, Any],
    version: str,
    config: Config,
    baseline: Baseline,
    now: datetime,
    *,
    fetch_archive: bool = True,
) -> PackageContext:
    """Assemble a ``PackageContext`` for one version from its packument."""
    name = str(packument.get("name") or packument.get("_id"))
    doc = packument["versions"][version]
    ordered = _times(packument)
    earlier = [v for _, v in ordered if v != version]
    previous = earlier[-1] if earlier else None
    prev_doc = packument["versions"].get(previous, {}) if previous else {}
    times = packument.get("time") or {}
    dist = doc.get("dist") or {}
    ctx = PackageContext(
        ecosystem="npm",
        name=name,
        version=version,
        config=config,
        baseline=baseline,
        description=doc.get("description") or packument.get("description"),
        readme=packument.get("readme") or doc.get("readme"),
        repository_url=clean_repo_url(doc.get("repository") or packument.get("repository")),
        homepage=doc.get("homepage") if isinstance(doc.get("homepage"), str) else None,
        maintainers=_names(doc.get("maintainers") or packument.get("maintainers")),
        previous_maintainers=_names(prev_doc.get("maintainers")) if previous else None,
        published_at=parse_ts(times.get(version)),
        package_created_at=parse_ts(times.get("created")) or (ordered[0][0] if ordered else None),
        version_count=len(packument.get("versions") or {}),
        previous_version=previous,
        size=dist.get("unpackedSize") if isinstance(dist.get("unpackedSize"), int) else None,
        previous_size=(prev_doc.get("dist") or {}).get("unpackedSize") if previous else None,
        manifest={k: v for k, v in doc.items() if not k.startswith("_")},
        archive_kinds=["tarball"],
    )
    ctx.publisher_is_new = _publisher_is_new(client, ctx, doc, now)
    tarball = dist.get("tarball")
    if fetch_archive and isinstance(tarball, str):
        if (ctx.size or 0) > int(config.limits["max_uncompressed_bytes"]):
            ctx.archive_error = "skipped: unpacked size is above the uncompressed limit"
        elif host_allowed(tarball, TARBALL_HOSTS):
            limit = int(config.limits["max_download_bytes"])
            load_archive(client, ctx, tarball, f"{version}.tgz", limit)
        else:
            ctx.archive_error = "skipped: tarball is not hosted on the npm registry"
    return ctx


def _publisher_is_new(
    client: Client, ctx: PackageContext, doc: dict[str, Any], now: datetime
) -> bool | None:
    created = ctx.package_created_at
    if created is None:
        return None
    if now - created > timedelta(days=NEW_PACKAGE_DAYS):
        return False
    # Only spend a search request when the name already resembles a popular package.
    if best_match(ctx.name, ctx.ecosystem, ctx.baseline, ctx.config) is None:
        return None
    user = (doc.get("_npmUser") or {}).get("name")
    if not isinstance(user, str) or " " in user or not user:
        user = ctx.maintainers[0] if ctx.maintainers else None
    if not user:
        return None
    count = publisher_package_count(client, user)
    return None if count is None else count <= NEW_PUBLISHER_MAX_PACKAGES
