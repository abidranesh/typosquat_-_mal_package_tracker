"""Core data types shared by sources, detectors and outputs."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from functools import cached_property
from typing import Any

from .baseline import Baseline
from .config import Config

SEVERITIES = ("info", "low", "medium", "high")
SNIPPET_MAX = 200

TEXT_SUFFIXES = (
    ".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".py", ".pyw", ".sh", ".bash", ".ps1", ".bat",
    ".cmd", ".pth", ".json", ".cfg", ".toml", ".yml", ".yaml",
)  # fmt: skip
CODE_SUFFIXES = (
    ".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".py", ".pyw", ".sh", ".bash", ".ps1", ".bat",
    ".cmd", ".pth",
)  # fmt: skip


def truncate(text: str, limit: int = SNIPPET_MAX) -> str:
    """Collapse whitespace and cut to ``limit`` characters (ellipsis included)."""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


@dataclass(frozen=True)
class Evidence:
    path: str
    snippet: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "snippet", truncate(self.snippet))


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    weight: int
    message: str
    evidence: Evidence | None = None
    target: str | None = None  # the popular package this one may be imitating

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "severity": self.severity,
            "weight": self.weight,
            "message": self.message,
        }
        if self.evidence:
            out["evidence"] = {"path": self.evidence.path, "snippet": self.evidence.snippet}
        if self.target:
            out["target"] = self.target
        return out


@dataclass
class PackageContext:
    """Everything a detector may look at. Detectors must treat it as read-only."""

    ecosystem: str  # "npm" or "pypi"
    name: str
    version: str
    config: Config
    baseline: Baseline
    description: str | None = None
    readme: str | None = None
    repository_url: str | None = None
    homepage: str | None = None
    maintainers: list[str] = field(default_factory=list)
    previous_maintainers: list[str] | None = None
    published_at: datetime | None = None
    package_created_at: datetime | None = None
    publisher_is_new: bool | None = None  # None means "could not be determined"
    version_count: int = 1
    previous_version: str | None = None
    size: int | None = None
    previous_size: int | None = None
    manifest: dict[str, Any] = field(default_factory=dict)  # npm package.json of this version
    archive_kinds: list[str] = field(default_factory=list)  # e.g. ["sdist", "wheel:none-any"]
    files: dict[str, bytes] = field(default_factory=dict)
    file_sizes: dict[str, int] = field(default_factory=dict)
    archive_error: str | None = None

    @property
    def is_first_release(self) -> bool:
        return self.version_count <= 1

    @property
    def key(self) -> str:
        return f"{self.ecosystem}/{self.name}/{self.version}"

    @cached_property
    def texts(self) -> dict[str, str]:
        """Decoded contents of text-like files, keyed by path."""
        out: dict[str, str] = {}
        for path, data in self.files.items():
            if path.lower().endswith(TEXT_SUFFIXES) and b"\x00" not in data[:4096]:
                out[path] = data.decode("utf-8", errors="replace")
        return out

    @cached_property
    def code(self) -> dict[str, str]:
        """Text files that hold executable source code."""
        return {p: t for p, t in self.texts.items() if p.lower().endswith(CODE_SUFFIXES)}

    @cached_property
    def scan_code(self) -> dict[str, str]:
        """Code files for pattern scanning, bounded so one huge package cannot stall a run.

        Shallow and small files come first: install-time and entry-point code lives near
        the package root, and that is where planted code is normally found.
        """
        budget = int(self.config.limits["max_scan_bytes"])
        per_file = int(self.config.limits["max_scan_file_bytes"])
        out: dict[str, str] = {}
        for path in sorted(self.code, key=lambda p: (p.count("/"), len(self.code[p]), p)):
            text = self.code[path][:per_file]
            if len(text) > budget:
                break
            budget -= len(text)
            out[path] = text
        return out

    @cached_property
    def package_json(self) -> dict[str, Any]:
        """The npm manifest: registry metadata if present, else the archive's package.json."""
        if self.manifest:
            return self.manifest
        candidates = sorted(
            (p for p in self.texts if p.endswith("package.json") and p.count("/") <= 1),
            key=len,
        )
        for path in candidates:
            try:
                parsed = json.loads(self.texts[path])
            except ValueError:
                continue
            if isinstance(parsed, dict):
                return parsed
        return {}

    @property
    def total_code_bytes(self) -> int:
        return sum(len(t) for t in self.code.values())
