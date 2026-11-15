"""Detector registry. Each detector is a pure function ``(PackageContext) -> list[Finding]``."""

from __future__ import annotations

from collections.abc import Callable

from ..context import Finding, PackageContext
from . import binaries, exfil, install_hooks, metadata, names, obfuscation, python_ast

Detector = Callable[[PackageContext], list[Finding]]

NAME_DETECTORS: tuple[Detector, ...] = names.DETECTORS
METADATA_DETECTORS: tuple[Detector, ...] = metadata.DETECTORS
CONTENT_DETECTORS: tuple[Detector, ...] = (
    *install_hooks.DETECTORS,
    *python_ast.DETECTORS,
    *obfuscation.DETECTORS,
    *exfil.DETECTORS,
    *binaries.DETECTORS,
)
ALL_DETECTORS: tuple[Detector, ...] = (*NAME_DETECTORS, *METADATA_DETECTORS, *CONTENT_DETECTORS)

# Every finding id a detector can emit, with a one-line description for the dashboard.
FINDING_IDS: dict[str, str] = {
    "typosquat": "Name within a small edit distance of a popular package",
    "name-manipulation": "Separator, look-alike character, affix or scope tricks on a popular name",
    "combosquat": "Popular name combined with generic words",
    "dependency-confusion": "Internal-looking name or implausibly high first version",
    "new-publisher-similar-name": "New publisher using a name close to a popular package",
    "sparse-metadata": "Missing description, README or repository link",
    "repo-impersonation": "Repository link points at the imitated package's repository",
    "popular-package-change": "Unusual maintainer, size or version change on a popular package",
    "npm-install-hook": "npm script that runs automatically at install time",
    "python-install-code": "setup.py or .pth code that runs at install or start-up",
    "obfuscation": "Hidden, encoded or unreadable code",
    "exfiltration": "Credential or environment access combined with network calls",
    "suspicious-endpoint": "Hardcoded webhook, tunnel, paste host or raw IP address",
    "binary-dropper": "Unexpected executable, or code that downloads and runs one",
    "unsafe-archive": "Archive with path-traversal entries",
}
