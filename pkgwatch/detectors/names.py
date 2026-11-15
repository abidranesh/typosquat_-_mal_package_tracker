"""Name-based detectors: typosquats, manipulations, combosquats, dependency confusion.

These only look at the package name and version, so they are cheap enough to run on
every package before anything is downloaded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta

from rapidfuzz import process
from rapidfuzz.distance import DamerauLevenshtein

from ..baseline import Baseline, canon_glyphs, normalize, squash
from ..config import Config
from ..context import Finding, PackageContext
from ..util import utcnow

_TOKEN_SPLIT = re.compile(r"[-_.]+")
_TRAILING_DIGITS = re.compile(r"\d+$")


@dataclass(frozen=True)
class NameMatch:
    target: str
    kind: str  # typo | homoglyph | separator | affix | scope | combosquat
    detail: str
    distance: int = 0


def _allowlisted(name: str, config: Config) -> bool:
    return name in set(config.names.get("allowlist", []))


def _scope_match(name: str, baseline: Baseline) -> NameMatch | None:
    """Scope confusion in either direction (npm only)."""
    scopes = baseline.scopes
    if name.startswith("@") and "/" in name:
        scope, bare = name[1:].split("/", 1)
        if scope in scopes or len(scope) < 4:
            return None
        for popular in scopes:
            if abs(len(popular) - len(scope)) <= 1 and (
                DamerauLevenshtein.distance(scope, popular, score_cutoff=1) <= 1
            ):
                target = f"@{popular}/{bare}" if bare in scopes[popular] else f"@{popular}"
                return NameMatch(target, "scope", f"scope @{scope} imitates @{popular}", 1)
        return None
    target = baseline.scope_lookalikes.get(name)
    if target:
        kind = "copy" if name == target.split("/", 1)[1] else "look-alike"
        return NameMatch(target, "scope", f"unscoped {kind} of {target}")
    return None


def _affix_match(name: str, baseline: Baseline, config: Config) -> NameMatch | None:
    minimum = int(config.names["min_name_length"])
    for prefix in config.names["prefixes"]:
        rest = name[len(prefix) :]
        if name.startswith(prefix) and len(rest) >= minimum and rest in baseline:
            return NameMatch(rest, "affix", f"popular name with added prefix '{prefix}'")
    for suffix in config.names["suffixes"]:
        rest = name[: -len(suffix)]
        if name.endswith(suffix) and len(rest) >= minimum and rest in baseline:
            return NameMatch(rest, "affix", f"popular name with added suffix '{suffix}'")
    return None


def find_manipulation(
    name: str, ecosystem: str, baseline: Baseline, config: Config
) -> NameMatch | None:
    """Deliberate-looking transformations of a popular name."""
    norm = normalize(name, ecosystem)
    if norm in baseline or _allowlisted(norm, config):
        return None
    if ecosystem == "npm":
        scope = _scope_match(norm, baseline)
        if scope or norm.startswith("@"):
            return scope
    if len(norm) < int(config.names["min_name_length"]):
        return None
    target = baseline.squashed.get(squash(norm))
    if target and target != norm:
        return NameMatch(target, "separator", "same name with separators changed")
    target = baseline.glyph_canon.get(canon_glyphs(norm))
    if target and target != norm and len(target) >= int(config.names["min_name_length"]):
        return NameMatch(target, "homoglyph", "look-alike characters (rn/m, 1/l, 0/o, vv/w)")
    return _affix_match(norm, baseline, config)


def _describe_edit(name: str, target: str) -> str:
    if len(name) == len(target):
        diff = [i for i, (a, b) in enumerate(zip(name, target, strict=True)) if a != b]
        if len(diff) == 2 and diff[1] == diff[0] + 1 and name[diff[0]] == target[diff[1]]:
            return "two adjacent characters swapped"
        return "one character substituted"
    if len(name) == len(target) + 1:
        for i in range(len(name)):
            if name[:i] + name[i + 1 :] == target:
                doubled = (i > 0 and name[i] == name[i - 1]) or (
                    i + 1 < len(name) and name[i] == name[i + 1]
                )
                return "a letter doubled" if doubled else "one extra character"
    if len(name) + 1 == len(target):
        return "one character missing"
    return "one edit"


def find_typo(name: str, ecosystem: str, baseline: Baseline, config: Config) -> NameMatch | None:
    """Damerau-Levenshtein neighbour of a popular name (<= 2, or <= 1 for short names)."""
    norm = normalize(name, ecosystem)
    cfg = config.names
    if (
        norm in baseline
        or norm.startswith("@")
        or len(norm) < int(cfg["min_name_length"])
        or _allowlisted(norm, config)
    ):
        return None
    cache: dict[str, NameMatch | None] = baseline.__dict__.setdefault("_typo_cache", {})
    if norm not in cache:
        if len(cache) > 50_000:
            cache.clear()
        cache[norm] = _search_typo(norm, baseline, config)
    return cache[norm]


def _search_typo(norm: str, baseline: Baseline, config: Config) -> NameMatch | None:
    cfg = config.names
    limit = 1 if len(norm) <= int(cfg["short_name_length"]) else 2
    pool = baseline.typo_pool(int(cfg["typosquat_top_n"]))
    hits = process.extract(
        norm, pool, scorer=DamerauLevenshtein.distance, score_cutoff=limit, limit=5
    )
    best: NameMatch | None = None
    for target, distance, _ in sorted(hits, key=lambda h: (h[1], baseline.rank[h[0]])):
        distance = int(distance)
        if distance == 0:
            continue
        if len(target) <= int(cfg["short_name_length"]) and distance > 1:
            continue
        # "foo2" next to "foo3" (or "foo") is a version suffix, not a typo.
        if _TRAILING_DIGITS.sub("", norm) == _TRAILING_DIGITS.sub("", target):
            continue
        detail = _describe_edit(norm, target) if distance == 1 else "two edits apart"
        best = NameMatch(target, "typo", detail, distance)
        break
    return best


def find_combosquat(
    name: str, ecosystem: str, baseline: Baseline, config: Config
) -> NameMatch | None:
    """A popular name joined to generic words, e.g. ``lodash-helper``."""
    norm = normalize(name, ecosystem)
    if norm in baseline or norm.startswith("@") or _allowlisted(norm, config):
        return None
    tokens = [t for t in _TOKEN_SPLIT.split(norm) if t]
    if len(tokens) < 2:
        return None
    generic = set(config.names["generic_words"])
    popular = set(baseline.top(int(config.names["combosquat_top_n"])))
    for start in range(len(tokens)):
        for end in range(start + 1, len(tokens) + 1):
            candidate = "-".join(tokens[start:end])
            rest = tokens[:start] + tokens[end:]
            if (
                rest
                and len(candidate) >= 5
                and candidate in popular
                and all(t in generic for t in rest)
            ):
                return NameMatch(
                    candidate, "combosquat", f"popular name plus generic word(s): {' '.join(rest)}"
                )
    return None


def best_match(name: str, ecosystem: str, baseline: Baseline, config: Config) -> NameMatch | None:
    """The strongest name similarity, used by the name and metadata detectors alike."""
    return (
        find_manipulation(name, ecosystem, baseline, config)
        or find_typo(name, ecosystem, baseline, config)
        or find_combosquat(name, ecosystem, baseline, config)
    )


def _scaled(ctx: PackageContext, weight: int) -> int:
    """Halve name weights for packages that have existed for a long time."""
    created = ctx.package_created_at
    days = int(ctx.config.names["established_days"])
    if created and utcnow() - created > timedelta(days=days):
        return weight // 2
    return weight


def _severity(weight: int) -> str:
    return "medium" if weight >= 25 else "low"


def detect_typosquat(ctx: PackageContext) -> list[Finding]:
    if find_manipulation(ctx.name, ctx.ecosystem, ctx.baseline, ctx.config):
        return []
    match = find_typo(ctx.name, ctx.ecosystem, ctx.baseline, ctx.config)
    if not match:
        return []
    short = len(normalize(ctx.name, ctx.ecosystem)) <= int(ctx.config.names["short_name_length"])
    key = "typosquat_short_name" if short else f"typosquat_distance_{match.distance}"
    weight = _scaled(ctx, ctx.config.weight(key))
    return [
        Finding(
            "typosquat",
            _severity(weight),
            weight,
            f"Name is {match.distance} edit(s) from popular package '{match.target}' "
            f"({match.detail}).",
            target=match.target,
        )
    ]


_MANIPULATION_WEIGHTS = {
    "homoglyph": "homoglyph",
    "separator": "separator_swap",
    "affix": "affix",
    "scope": "scope_confusion",
}


def detect_name_manipulation(ctx: PackageContext) -> list[Finding]:
    match = find_manipulation(ctx.name, ctx.ecosystem, ctx.baseline, ctx.config)
    if not match:
        return []
    weight = _scaled(ctx, ctx.config.weight(_MANIPULATION_WEIGHTS[match.kind]))
    return [
        Finding(
            "name-manipulation",
            _severity(weight),
            weight,
            f"Name resembles popular package '{match.target}': {match.detail}.",
            target=match.target,
        )
    ]


def detect_combosquat(ctx: PackageContext) -> list[Finding]:
    if find_manipulation(ctx.name, ctx.ecosystem, ctx.baseline, ctx.config) or find_typo(
        ctx.name, ctx.ecosystem, ctx.baseline, ctx.config
    ):
        return []
    match = find_combosquat(ctx.name, ctx.ecosystem, ctx.baseline, ctx.config)
    if not match:
        return []
    weight = _scaled(ctx, ctx.config.weight("combosquat"))
    return [
        Finding(
            "combosquat",
            "low",
            weight,
            f"Name combines popular package '{match.target}' with generic words "
            f"({match.detail.split(': ', 1)[1]}).",
            target=match.target,
        )
    ]


def _major(version: str) -> int | None:
    head = re.match(r"v?(\d+)", version.strip())
    return int(head.group(1)) if head else None


def detect_dependency_confusion(ctx: PackageContext) -> list[Finding]:
    """Internal-looking names published with an implausibly high version."""
    major = _major(ctx.version)
    threshold = int(ctx.config.names["dependency_confusion_major"])
    # Calendar versions (2024.1.0) are legitimate; only flag the 90..999 band.
    if major is None or not threshold <= major < 1000 or ctx.version_count > 3:
        return []
    if normalize(ctx.name, ctx.ecosystem) in ctx.baseline:
        return []
    bare = ctx.name.split("/", 1)[-1].lower()
    tokens = set(_TOKEN_SPLIT.split(bare))
    markers = [m for m in ctx.config.names["internal_markers"] if m in tokens or m in bare]
    if markers:
        return [
            Finding(
                "dependency-confusion",
                "high",
                ctx.config.weight("dependency_confusion"),
                f"Internal-looking name ('{markers[0]}') first published at version "
                f"{ctx.version}; this pattern is used to hijack private dependency names.",
            )
        ]
    if ctx.is_first_release:
        return [
            Finding(
                "dependency-confusion",
                "low",
                ctx.config.weight("high_first_version"),
                f"First published version is {ctx.version}, far above a normal starting version.",
            )
        ]
    return []


DETECTORS = (
    detect_typosquat,
    detect_name_manipulation,
    detect_combosquat,
    detect_dependency_confusion,
)
