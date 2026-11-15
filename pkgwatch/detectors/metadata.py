"""Metadata-based detectors: publisher age, sparse metadata, impersonation, popular changes."""

from __future__ import annotations

import re

from ..baseline import normalize
from ..context import Finding, PackageContext
from .names import best_match

_PLACEHOLDERS = (
    "unknown",
    "todo",
    "tbd",
    "description",
    "no description",
    "a package",
    "test",
    "error: no readme data found!",
    "add your description here",
)


def _blank(text: str | None, minimum: int = 1) -> bool:
    if not isinstance(text, str):
        return True
    stripped = text.strip()
    return len(stripped) < minimum or stripped.lower().rstrip(".") in _PLACEHOLDERS


def detect_new_publisher(ctx: PackageContext) -> list[Finding]:
    """A brand-new publisher whose package name resembles a popular one."""
    if ctx.publisher_is_new is not True:
        return []
    match = best_match(ctx.name, ctx.ecosystem, ctx.baseline, ctx.config)
    if not match:
        return []
    return [
        Finding(
            "new-publisher-similar-name",
            "medium",
            ctx.config.weight("new_publisher_similar_name"),
            f"Recently created package from a publisher with little history, with a name "
            f"similar to popular package '{match.target}'.",
            target=match.target,
        )
    ]


def detect_sparse_metadata(ctx: PackageContext) -> list[Finding]:
    """Missing or placeholder description, README or repository link."""
    if normalize(ctx.name, ctx.ecosystem) in ctx.baseline:
        return []
    missing = []
    if _blank(ctx.description):
        missing.append("description")
    if _blank(ctx.readme, 40):
        missing.append("README")
    if not ctx.repository_url:
        missing.append("repository URL")
    if not missing:
        return []
    return [
        Finding(
            "sparse-metadata",
            "info",
            ctx.config.weight("sparse_metadata_each") * len(missing),
            f"Missing or placeholder {', '.join(missing)}.",
        )
    ]


def _repo_name(url: str) -> str:
    return re.sub(r"\.git$", "", url.rstrip("/").rsplit("/", 1)[-1]).lower()


def detect_repo_impersonation(ctx: PackageContext) -> list[Finding]:
    """The repository link points at the repo of the popular package being imitated."""
    if not ctx.repository_url:
        return []
    match = best_match(ctx.name, ctx.ecosystem, ctx.baseline, ctx.config)
    if not match or match.kind in ("scope", "combosquat", "affix"):
        return []
    repo = _repo_name(ctx.repository_url)
    target = match.target.split("/", 1)[-1]
    own = normalize(ctx.name, ctx.ecosystem)
    if normalize(repo, ctx.ecosystem) != normalize(target, ctx.ecosystem) or repo == own:
        return []
    return [
        Finding(
            "repo-impersonation",
            "medium",
            ctx.config.weight("repo_impersonation"),
            f"Repository URL points at a repo named '{repo}', matching popular package "
            f"'{match.target}' rather than this package.",
            target=match.target,
        )
    ]


def _major(version: str | None) -> int | None:
    head = re.match(r"v?(\d+)", (version or "").strip())
    return int(head.group(1)) if head else None


def detect_popular_change(ctx: PackageContext) -> list[Finding]:
    """Unusual changes on a package that is itself popular."""
    if normalize(ctx.name, ctx.ecosystem) not in ctx.baseline or not ctx.previous_version:
        return []
    out = []
    if ctx.previous_maintainers:
        added = sorted(set(ctx.maintainers) - set(ctx.previous_maintainers))
        if added:
            out.append(
                Finding(
                    "popular-package-change",
                    "low",
                    ctx.config.weight("popular_new_maintainer"),
                    f"Popular package gained maintainer(s) since {ctx.previous_version}: "
                    f"{', '.join(added[:5])}.",
                )
            )
    if ctx.size and ctx.previous_size and ctx.previous_size > 0:
        ratio = ctx.size / ctx.previous_size
        if (ratio >= 3 or ratio <= 1 / 3) and abs(ctx.size - ctx.previous_size) > 100_000:
            out.append(
                Finding(
                    "popular-package-change",
                    "low",
                    ctx.config.weight("popular_size_jump"),
                    f"Popular package changed size {ratio:.1f}x since {ctx.previous_version} "
                    f"({ctx.previous_size} to {ctx.size} bytes).",
                )
            )
    now, before = _major(ctx.version), _major(ctx.previous_version)
    if now is not None and before is not None and now - before >= 5 and now < 1000:
        out.append(
            Finding(
                "popular-package-change",
                "low",
                ctx.config.weight("popular_version_jump"),
                f"Popular package jumped from version {ctx.previous_version} to {ctx.version}.",
            )
        )
    return out


DETECTORS = (
    detect_new_publisher,
    detect_sparse_metadata,
    detect_repo_impersonation,
    detect_popular_change,
)
