"""Probe every upstream data source and print what it currently returns.

Run ``python scripts/probe_sources.py`` whenever a source misbehaves. The findings from
the last manual run are recorded in DECISIONS.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pkgwatch.config import load_config  # noqa: E402
from pkgwatch.http import Client, HttpError  # noqa: E402
from pkgwatch.sources import baselines, npm, pypi  # noqa: E402


def probe(label: str, fn) -> bool:
    try:
        print(f"[ok]   {label}: {fn()}")
        return True
    except (HttpError, KeyError, ValueError, TypeError) as exc:
        print(f"[FAIL] {label}: {type(exc).__name__}: {exc}")
        return False


def main() -> int:
    with Client(load_config()) as client:

        def changes() -> str:
            seq = npm.current_seq(client)
            rows, last = npm.fetch_changes(client, seq - 200, 50)
            return f"update_seq={seq}, {len(rows)} changes after seq-200, resume at {last}"

        def packument() -> str:
            doc = npm.fetch_packument(client, "left-pad")
            return f"left-pad keys={sorted(doc)[:6]}..., {len(doc['versions'])} versions"

        def changelog() -> str:
            serial = pypi.last_serial(client)
            rows, last = pypi.changelog_since(client, serial - 300)
            return f"last_serial={serial}, {len(rows)} releases in the last 300 serials"

        def project() -> str:
            doc = pypi.fetch_project(client, "requests")
            return f"requests keys={sorted(doc)}, {len(doc['releases'])} releases"

        checks = [
            ("npm replication root + _changes", changes),
            ("npm packument", packument),
            ("npm search (maintainer count)", lambda: npm.publisher_package_count(client, "npm")),
            ("PyPI packages.xml", lambda: len(pypi.fetch_rss(client, pypi.RSS_NEW, None)[0])),
            ("PyPI updates.xml", lambda: len(pypi.fetch_rss(client, pypi.RSS_UPDATES, None)[0])),
            ("PyPI XML-RPC changelog", changelog),
            ("PyPI JSON API", project),
            ("PyPI baseline list", lambda: len(baselines.fetch_pypi(client))),
            ("npm baseline list", lambda: len(baselines.fetch_npm(client))),
        ]
        results = [probe(label, fn) for label, fn in checks]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
