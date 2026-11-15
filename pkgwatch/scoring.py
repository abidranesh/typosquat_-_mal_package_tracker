"""Run detectors over a package and turn findings into a risk score."""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import Config
from .context import Finding, PackageContext
from .detectors import ALL_DETECTORS, Detector


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    severity: str | None = None  # None means "below the listing threshold"
    errors: list[str] = field(default_factory=list)

    @property
    def listed(self) -> bool:
        return self.severity is not None


def score_findings(findings: list[Finding], config: Config) -> int:
    """Sum of weights, capped at the configured maximum."""
    return min(sum(f.weight for f in findings), int(config.thresholds["max_score"]))


def severity_for(score: int, config: Config) -> str | None:
    thresholds = config.thresholds
    if score >= thresholds["high"]:
        return "high"
    if score >= thresholds["medium"]:
        return "medium"
    if score >= thresholds["low"]:
        return "low"
    return None


def analyze(ctx: PackageContext, detectors: tuple[Detector, ...] = ALL_DETECTORS) -> Result:
    """Run every detector. A crashing detector is recorded, never fatal."""
    result = Result()
    for detector in detectors:
        try:
            result.findings.extend(detector(ctx))
        except Exception as exc:  # noqa: BLE001 - hostile input must not stop a scan
            result.errors.append(f"{detector.__name__}: {type(exc).__name__}: {exc}")
    result.findings.sort(key=lambda f: -f.weight)
    result.score = score_findings(result.findings, ctx.config)
    result.severity = severity_for(result.score, ctx.config)
    return result
