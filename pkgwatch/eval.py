"""Evaluate the detectors against the fixture corpus (``python -m pkgwatch.eval``).

Prints precision and recall per finding id and enforces two gates:

* recall on malicious fixtures (share scoring at or above the "medium" threshold);
* no clean fixture may score at or above the "medium" threshold.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config, load_config
from .detectors import FINDING_IDS
from .fixtures import DEFAULT_DIR, Fixture, load_fixtures
from .scoring import Result, analyze

MIN_RECALL = 0.90


@dataclass
class Tally:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None


@dataclass
class Report:
    rows: list[tuple[Fixture, Result]] = field(default_factory=list)
    tallies: dict[str, Tally] = field(default_factory=dict)
    recall: float = 0.0
    missed: list[str] = field(default_factory=list)
    noisy_clean: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.recall >= MIN_RECALL and not self.noisy_clean and not self.errors


def evaluate(config: Config, directory: Path | str = DEFAULT_DIR) -> Report:
    report = Report(tallies={finding_id: Tally() for finding_id in FINDING_IDS})
    fixtures = load_fixtures(config, directory)
    medium = int(config.thresholds["medium"])
    malicious = caught = 0
    for fixture in fixtures:
        result = analyze(fixture.ctx)
        report.rows.append((fixture, result))
        report.errors.extend(f"{fixture.id}: {e}" for e in result.errors)
        fired = {f.id for f in result.findings}
        expected = set(fixture.expected)
        for finding_id in fired | expected:
            tally = report.tallies.setdefault(finding_id, Tally())
            if finding_id in fired and finding_id in expected:
                tally.tp += 1
            elif finding_id in expected:
                tally.fn += 1
            elif finding_id not in fixture.allowed:
                tally.fp += 1
        if fixture.label == "malicious":
            malicious += 1
            if result.score >= medium:
                caught += 1
            else:
                report.missed.append(f"{fixture.id} (score {result.score})")
        elif result.score >= medium:
            report.noisy_clean.append(f"{fixture.id} (score {result.score})")
    report.recall = caught / malicious if malicious else 0.0
    return report


def _pct(value: float | None) -> str:
    return "   -  " if value is None else f"{value * 100:5.1f}%"


def render(report: Report) -> str:
    lines = [f"{'fixture':44} {'label':9} {'score':>5}  severity  findings"]
    for fixture, result in report.rows:
        ids = ", ".join(sorted({f.id for f in result.findings})) or "-"
        lines.append(
            f"{fixture.id:44} {fixture.label:9} {result.score:5d}  "
            f"{result.severity or 'unlisted':8}  {ids}"
        )
    lines += ["", f"{'detector':30} {'TP':>3} {'FP':>3} {'FN':>3}  precision  recall"]
    for finding_id, tally in sorted(report.tallies.items()):
        lines.append(
            f"{finding_id:30} {tally.tp:3d} {tally.fp:3d} {tally.fn:3d}    "
            f"{_pct(tally.precision)}  {_pct(tally.recall)}"
        )
    lines += ["", f"malicious-fixture recall: {report.recall * 100:.1f}% (gate {MIN_RECALL:.0%})"]
    for label, items in (
        ("missed malicious fixtures", report.missed),
        ("clean fixtures at or above medium", report.noisy_clean),
        ("detector errors", report.errors),
    ):
        if items:
            lines.append(f"{label}: " + "; ".join(items))
    lines.append("RESULT: " + ("PASS" if report.passed else "FAIL"))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fixtures", default=str(DEFAULT_DIR), help="fixture directory")
    args = parser.parse_args(argv)
    report = evaluate(load_config(), args.fixtures)
    print(render(report))
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
