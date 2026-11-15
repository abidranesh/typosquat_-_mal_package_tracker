"""Helpers shared by the npm and PyPI sources."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..archive import ArchiveError, Limits, UnsafePath, read_archive
from ..context import PackageContext
from ..http import Client, HttpError, TooLarge

_REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sr.ht")
_GIT_PREFIX = re.compile(r"^(git\+)?(git|ssh|https?)://(git@)?|^git@|^github:")


def clean_repo_url(value: object) -> str | None:
    """Normalise the many spellings of a repository URL to ``https://host/owner/repo``."""
    if isinstance(value, dict):
        value = value.get("url")
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.startswith("github:"):
        text = "https://github.com/" + text[len("github:") :]
    elif text.startswith("git@"):
        text = "https://" + text[len("git@") :].replace(":", "/", 1)
    else:
        text = _GIT_PREFIX.sub("https://", text)
    if re.fullmatch(r"[\w.-]+/[\w.-]+", text):
        text = "https://github.com/" + text  # npm shorthand "owner/repo"
    if not text.startswith("https://"):
        return None
    text = text.split("#", 1)[0].rstrip("/")
    return text.removesuffix(".git")


def is_repo_host(url: str | None) -> bool:
    if not url:
        return False
    host = urlsplit(url).hostname or ""
    return any(host == h or host.endswith("." + h) for h in _REPO_HOSTS)


def host_allowed(url: str, allowed: tuple[str, ...]) -> bool:
    parts = urlsplit(url)
    return parts.scheme == "https" and (parts.hostname or "") in allowed


def load_archive(
    client: Client,
    ctx: PackageContext,
    url: str,
    filename: str,
    max_bytes: int,
) -> int:
    """Download one archive into ``ctx.files``. Returns bytes downloaded (0 on failure).

    Failures are recorded on ``ctx.archive_error`` rather than raised: a package whose
    archive cannot be read is still scored on its name and metadata.
    """
    try:
        body = client.get(url, max_bytes=max_bytes).body
    except TooLarge:
        ctx.archive_error = ctx.archive_error or "skipped: archive larger than the download limit"
        return 0
    except HttpError as exc:
        ctx.archive_error = ctx.archive_error or f"skipped: download failed ({exc})"
        return 0
    try:
        contents = read_archive(body, filename, Limits.from_config(ctx.config))
    except UnsafePath as exc:
        ctx.archive_error = f"unsafe: {exc}"
        return len(body)
    except ArchiveError as exc:
        ctx.archive_error = ctx.archive_error or f"skipped: {exc}"
        return len(body)
    ctx.files.update(contents.files)
    ctx.file_sizes.update(contents.sizes)
    return len(body)
