"""Popular-package baselines: the names a typosquat would imitate."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

DEFAULT_DIR = Path(__file__).resolve().parent.parent / "data" / "baselines"
_SEPARATORS = re.compile(r"[-_.]+")


def normalize(name: str, ecosystem: str) -> str:
    """Canonical comparison form. PyPI names are folded per PEP 503."""
    lowered = name.strip().lower()
    if ecosystem == "pypi":
        return _SEPARATORS.sub("-", lowered)
    return lowered


def squash(name: str) -> str:
    """Drop every separator, so ``python-dateutil`` and ``pythondateutil`` collide."""
    return _SEPARATORS.sub("", name)


def canon_glyphs(name: str) -> str:
    """Fold look-alike characters onto one spelling."""
    return name.replace("rn", "m").replace("vv", "w").replace("1", "l").replace("0", "o")


@dataclass
class Baseline:
    """Popular names for one ecosystem, most popular first."""

    ecosystem: str
    names: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        seen: dict[str, None] = {}
        for name in self.names:
            seen.setdefault(normalize(name, self.ecosystem), None)
        self.names = list(seen)

    @cached_property
    def rank(self) -> dict[str, int]:
        return {name: i for i, name in enumerate(self.names)}

    def __contains__(self, name: str) -> bool:
        return normalize(name, self.ecosystem) in self.rank

    def top(self, n: int) -> list[str]:
        return self.names[:n]

    @cached_property
    def unscoped(self) -> list[str]:
        return [n for n in self.names if not n.startswith("@")]

    @cached_property
    def squashed(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for name in self.unscoped:
            out.setdefault(squash(name), name)
        return out

    @cached_property
    def glyph_canon(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for name in self.unscoped:
            out.setdefault(canon_glyphs(name), name)
        return out

    @cached_property
    def scopes(self) -> dict[str, list[str]]:
        """Popular npm scopes (without ``@``) mapped to their popular package names."""
        out: dict[str, list[str]] = {}
        for name in self.names:
            if name.startswith("@") and "/" in name:
                scope, bare = name[1:].split("/", 1)
                out.setdefault(scope, []).append(bare)
        return out

    @cached_property
    def scope_lookalikes(self) -> dict[str, str]:
        """Unscoped spellings that imitate a popular scoped package, mapped to that package."""
        out: dict[str, str] = {}
        for scope, packages in self.scopes.items():
            for bare in packages:
                target = f"@{scope}/{bare}"
                for sep in ("-", "", "_", "."):
                    out.setdefault(f"{scope}{sep}{bare}", target)
                if len(bare) >= 8:
                    out.setdefault(bare, target)
        return out

    def typo_pool(self, top_n: int) -> list[str]:
        """Unscoped popular names long enough to be worth typosquatting (cached)."""
        cache = self.__dict__.setdefault("_typo_pools", {})
        if top_n not in cache:
            cache[top_n] = [n for n in self.unscoped[:top_n] if len(n) >= 4]
        return cache[top_n]


def load_baseline(ecosystem: str, directory: Path | str | None = None) -> Baseline:
    """Load ``<directory>/<ecosystem>-top.json``; a missing file yields an empty baseline."""
    path = Path(directory or DEFAULT_DIR) / f"{ecosystem}-top.json"
    if not path.exists():
        return Baseline(ecosystem, [])
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    return Baseline(ecosystem, list(doc.get("packages", [])))
