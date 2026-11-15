"""Refresh the popular-package baselines (``python -m pkgwatch.sources.baselines``)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from ..baseline import DEFAULT_DIR
from ..config import load_config
from ..http import Client, HttpError
from ..util import iso, utcnow, write_json

PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
NPM_URLS = (
    "https://cdn.jsdelivr.net/npm/npm-high-impact@latest/lib/top-download.js",
    "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top-download.js",
)
PYPI_TOP = 8000
NPM_TOP = 10000
MIN_NAMES = 1000
_MAX_BYTES = 8 * 1024 * 1024
_JS_NAME = re.compile(r"""^\s*['"]((?:@[a-z0-9~][\w.~-]*/)?[a-z0-9~][\w.~-]*)['"],?\s*$""", re.M)


class BaselineError(RuntimeError):
    """A refreshed list looked wrong, so the committed snapshot was left untouched."""


def fetch_pypi(client: Client) -> list[str]:
    doc = client.get_json(PYPI_URL, max_bytes=_MAX_BYTES)
    return [str(row["project"]) for row in doc["rows"] if row.get("project")][:PYPI_TOP]


def parse_npm_list(source: str) -> list[str]:
    """Extract package names from npm-high-impact's ``export const x = [...]`` module."""
    return _JS_NAME.findall(source)[:NPM_TOP]


def fetch_npm(client: Client) -> list[str]:
    last: Exception | None = None
    for url in NPM_URLS:
        try:
            names = parse_npm_list(client.get(url, max_bytes=_MAX_BYTES).body.decode("utf-8"))
        except HttpError as exc:
            last = exc
            continue
        if len(names) >= MIN_NAMES:
            return names
    raise BaselineError(f"no usable npm popularity list ({last})")


def write_baseline(directory: Path, ecosystem: str, names: list[str], source: str) -> Path:
    if len(names) < MIN_NAMES:
        raise BaselineError(f"{ecosystem} list has only {len(names)} names; refusing to write")
    path = directory / f"{ecosystem}-top.json"
    doc = {"source": source, "updated": iso(utcnow())[:10], "count": len(names), "packages": names}
    write_json(path, doc)
    return path


def refresh(client: Client, directory: Path | str = DEFAULT_DIR) -> dict[str, int]:
    target = Path(directory)
    pypi = fetch_pypi(client)
    npm = fetch_npm(client)
    write_baseline(target, "pypi", pypi, PYPI_URL)
    write_baseline(target, "npm", npm, NPM_URLS[0])
    return {"pypi": len(pypi), "npm": len(npm)}


def main() -> int:
    with Client(load_config()) as client:
        counts = refresh(client)
    print(f"baselines refreshed: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
