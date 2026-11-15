import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from pkgwatch import eval as evaluation
from pkgwatch.context import SNIPPET_MAX, Evidence, Finding, truncate
from pkgwatch.detectors import ALL_DETECTORS, FINDING_IDS
from pkgwatch.fixtures import DEFAULT_DIR, load_fixtures
from pkgwatch.scoring import analyze, score_findings, severity_for

ROOT = Path(__file__).resolve().parent.parent


def finding(weight, finding_id="typosquat"):
    return Finding(finding_id, "low", weight, "message")


def test_score_is_sum_of_weights_capped_at_100(config):
    assert score_findings([], config) == 0
    assert score_findings([finding(25), finding(20)], config) == 45
    assert score_findings([finding(60), finding(70)], config) == 100


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (0, None),
        (14, None),
        (15, "low"),
        (39, "low"),
        (40, "medium"),
        (69, "medium"),
        (70, "high"),
        (100, "high"),
    ],
)
def test_severity_thresholds(config, score, severity):
    assert severity_for(score, config) == severity


def test_analyze_sorts_findings_and_sets_listing(make_ctx):
    result = analyze(make_ctx("pypi", "reqeusts", publisher_is_new=True, repository_url=None))
    assert [f.id for f in result.findings] == [
        "typosquat",
        "new-publisher-similar-name",
        "sparse-metadata",
    ]
    assert result.score == 49 and result.severity == "medium" and result.listed
    clean = analyze(make_ctx("npm", "zebra-crossing-timer"))
    assert clean.score == 0 and clean.severity is None and not clean.listed


def test_a_crashing_detector_is_recorded_and_does_not_stop_the_others(make_ctx):
    def broken(ctx):
        raise RuntimeError("boom")

    def fine(ctx):
        return [finding(20)]

    result = analyze(make_ctx(), detectors=(broken, fine))
    assert result.score == 20
    assert result.errors == ["broken: RuntimeError: boom"]


def test_finding_and_evidence_contracts():
    long = Evidence("a.js", "x" * 500)
    assert len(long.snippet) == SNIPPET_MAX and long.snippet.endswith("…")
    assert truncate("a\n   b\tc") == "a b c"
    # URLs and secrets are kept intact up to the limit, not masked.
    url = "https://example.invalid/api/webhooks/123/SECRET-TOKEN"
    assert Evidence("a.js", f'post("{url}")').snippet == f'post("{url}")'
    with pytest.raises(ValueError):
        Finding("x", "critical", 1, "m")
    full = Finding("typosquat", "medium", 25, "m", Evidence("p", "s"), "requests").to_dict()
    assert full == {
        "id": "typosquat",
        "severity": "medium",
        "weight": 25,
        "message": "m",
        "evidence": {"path": "p", "snippet": "s"},
        "target": "requests",
    }
    assert set(Finding("x", "info", 1, "m").to_dict()) == {"id", "severity", "weight", "message"}


def test_every_detector_only_emits_registered_ids(config):
    seen = set()
    for fixture in load_fixtures(config):
        for detector in ALL_DETECTORS:
            for item in detector(fixture.ctx):
                assert isinstance(item, Finding)
                assert 0 < item.weight <= 100
                seen.add(item.id)
    assert seen == set(FINDING_IDS)  # the corpus exercises every finding id


def test_all_weights_and_thresholds_come_from_config(config):
    assert config.thresholds == {"low": 15, "medium": 40, "high": 70, "max_score": 100}
    assert all(isinstance(v, int) and v > 0 for v in config.weights.values())
    source = "".join(
        p.read_text(encoding="utf-8") for p in (ROOT / "pkgwatch" / "detectors").glob("*.py")
    )
    used = set(re.findall(r'weight\(\s*f?"([a-z_0-9{}.]+)"', source))
    used |= set(re.findall(r'^\s+"[a-z_]+": \(\s*"([a-z_]+)"', source, re.M))
    literal = {key for key in used if "{" not in key}
    assert literal and literal <= set(config.weights)


# ---------------------------------------------------------------- evaluation


def test_eval_meets_recall_and_false_positive_gates(config):
    report = evaluation.evaluate(config)
    assert report.passed and report.recall >= 0.9
    assert not report.noisy_clean and not report.errors
    labels = [fixture.label for fixture, _ in report.rows]
    assert labels.count("malicious") >= 15 and labels.count("clean") >= 15
    medium = config.thresholds["medium"]
    for fixture, result in report.rows:
        fired = {f.id for f in result.findings}
        if fixture.label == "clean":
            assert result.score < medium, fixture.id
            assert fired <= set(fixture.allowed), fixture.id
        else:
            assert fired == set(fixture.expected), fixture.id
    for tally in report.tallies.values():
        assert tally.fp == 0 and tally.fn == 0
    text = evaluation.render(report)
    assert "malicious-fixture recall: 100.0%" in text and text.endswith("RESULT: PASS")


def test_eval_cli_exit_codes(tmp_path, capsys):
    assert evaluation.main([]) == 0
    assert "precision" in capsys.readouterr().out
    # A corpus with a missed malicious fixture and a noisy clean one must fail the gate.
    for kind in ("malicious", "clean", "baselines"):
        (tmp_path / kind).mkdir()
    for eco in ("npm", "pypi"):
        (tmp_path / "baselines" / f"{eco}-top.json").write_text(
            (DEFAULT_DIR / "baselines" / f"{eco}-top.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    missed = {
        "ecosystem": "npm",
        "name": "quiet-thing",
        "version": "1.0.0",
        "expected": ["obfuscation"],
    }
    (tmp_path / "malicious" / "missed.json").write_text(json.dumps(missed), encoding="utf-8")
    noisy = json.loads(
        (DEFAULT_DIR / "malicious" / "npm-lodahs-curl-postinstall.json").read_text(encoding="utf-8")
    )
    noisy["expected"] = []
    (tmp_path / "clean" / "noisy.json").write_text(json.dumps(noisy), encoding="utf-8")
    assert evaluation.main(["--fixtures", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert (
        "missed malicious fixtures: missed" in out
        and "clean fixtures at or above medium: noisy" in out
    )
    assert out.strip().endswith("RESULT: FAIL")


def test_tally_ratios():
    assert evaluation.Tally().precision is None and evaluation.Tally().recall is None
    tally = evaluation.Tally(tp=3, fp=1, fn=1)
    assert tally.precision == 0.75 and tally.recall == 0.75


# ---------------------------------------------------------------- fixture hygiene

_URL = re.compile(r"https?://([^/\s\"'`\\)]+)")
_ALLOWED_HOSTS = {
    "github.com",
    "pypi.org",
    "registry.npmjs.org",
    "discord.com",
    "deb.nodesource.com",
}


def test_fixtures_only_reference_reserved_hosts_and_documentation_addresses():
    for path in sorted(DEFAULT_DIR.glob("*/*.json")):
        spec = json.loads(path.read_text(encoding="utf-8"))
        malicious = path.parent.name == "malicious"
        for text in spec.get("files", {}).values():
            for host in _URL.findall(text):
                host = host.split(":")[0].lower()
                if host.endswith("example.invalid") or re.fullmatch(r"203\.0\.113\.\d+", host):
                    continue
                assert not malicious and host in _ALLOWED_HOSTS, f"{path.name}: {host}"


def test_fixture_payloads_are_inert():
    import base64

    spec = json.loads(
        (DEFAULT_DIR / "malicious" / "pypi-reqeusts-b64-setup.json").read_text(encoding="utf-8")
    )
    setup = spec["files"]["reqeusts-2.31.1/setup.py"]
    blob = re.search(r'payload = "([^"]+)"', setup).group(1)
    assert base64.b64decode(blob).decode().startswith("print('synthetic PkgWatch fixture")
    binary = json.loads(
        (DEFAULT_DIR / "malicious" / "pypi-bundled-binary-autostart.json").read_text(
            encoding="utf-8"
        )
    )
    (data,) = binary["files_b64"].values()
    assert base64.b64decode(data) == b"MZ" + b"\x00" * 126  # a magic number, not a program


def test_committed_fixtures_match_their_generator(tmp_path):
    script = (ROOT / "scripts" / "build_fixtures.py").read_text(encoding="utf-8")
    patched = tmp_path / "build_fixtures.py"
    patched.write_text(
        script.replace(
            'ROOT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"',
            f"ROOT = Path(r'{tmp_path}') / 'out'",
        ),
        encoding="utf-8",
    )
    subprocess.run([sys.executable, str(patched)], check=True, capture_output=True)
    generated = sorted(p.relative_to(tmp_path / "out") for p in (tmp_path / "out").rglob("*.json"))
    committed = sorted(p.relative_to(DEFAULT_DIR) for p in DEFAULT_DIR.rglob("*.json"))
    assert generated == committed
    for rel in generated:
        assert (tmp_path / "out" / rel).read_bytes() == (DEFAULT_DIR / rel).read_bytes(), rel
