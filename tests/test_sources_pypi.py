import xmlrpc.client
from datetime import UTC, datetime

import pytest
import respx

from pkgwatch.sources import baselines as baseline_source
from pkgwatch.sources import pypi
from pkgwatch.state import empty_state, load_state, save_state
from pkgwatch.util import iso, parse_ts, read_json, write_json
from tests.helpers import make_tgz, make_zip

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
FILES = "https://files.pythonhosted.org/packages/aa/bb"

UPDATES_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>PyPI recent updates</title>
<item><title>reqeusts 2.0.1</title><link>https://pypi.org/project/reqeusts/2.0.1/</link>
<description>HTTP</description><pubDate>Sun, 15 Nov 2026 10:03:03 GMT</pubDate></item>
<item><title>broken</title><link>https://pypi.org/</link></item>
<item><title>nodate 1.0</title><link>https://pypi.org/project/nodate/1.0/</link>
<pubDate>not a date</pubDate></item>
</channel></rss>"""
NEW_XML = b"""<rss version="2.0"><channel>
<item><title>freshpkg added to PyPI</title><link>https://pypi.org/project/freshpkg/</link>
<pubDate>Sun, 15 Nov 2026 09:02:02 GMT</pubDate></item></channel></rss>"""


def project(**overrides):
    def file(name, kind, size, when):
        return {
            "filename": name,
            "packagetype": kind,
            "size": size,
            "url": f"{FILES}/{name}",
            "upload_time_iso_8601": when,
        }

    doc = {
        "info": {
            "name": "reqeusts",
            "version": "2.0.1",
            "summary": "HTTP for humans",
            "description": "Long description " * 10,
            "home_page": "",
            "project_urls": {
                "Docs": "https://example.invalid/docs",
                "Source": "https://github.com/x/reqeusts/tree/main",
            },
        },
        "ownership": {"roles": [{"role": "Owner", "user": "newbie"}]},
        "releases": {
            "2.0.0": [file("reqeusts-2.0.0.tar.gz", "sdist", 900, "2026-11-10T08:00:00.000000Z")],
            "2.0.1": [
                file("reqeusts-2.0.1.tar.gz", "sdist", 1000, "2026-11-15T10:03:00.000000Z"),
                file(
                    "reqeusts-2.0.1-cp312-cp312-win_amd64.whl",
                    "bdist_wheel",
                    500,
                    "2026-11-15T10:03:01.000000Z",
                ),
                file(
                    "reqeusts-2.0.1-py3-none-any.whl",
                    "bdist_wheel",
                    800,
                    "2026-11-15T10:03:02.000000Z",
                ),
            ],
            "0.0.1": [],
        },
    }
    doc.update(overrides)
    return doc


def test_parse_rss_handles_updates_new_and_bad_items():
    updates = pypi.parse_rss(UPDATES_XML)
    assert [(r.name, r.version) for r in updates] == [("reqeusts", "2.0.1"), ("nodate", "1.0")]
    assert updates[0].published == datetime(2026, 11, 15, 10, 3, 3, tzinfo=UTC)
    assert updates[1].published is None
    assert [(r.name, r.version) for r in pypi.parse_rss(NEW_XML)] == [("freshpkg", None)]
    assert pypi.parse_rss(b"<rss><channel><item>") == []


@respx.mock
def test_fetch_rss_uses_etag_and_handles_304(client):
    route = respx.get(pypi.RSS_UPDATES).respond(content=UPDATES_XML, headers={"ETag": "e1"})
    items, etag = pypi.fetch_rss(client, pypi.RSS_UPDATES, None)
    assert len(items) == 2 and etag == "e1"
    route.respond(304)
    items, etag = pypi.fetch_rss(client, pypi.RSS_UPDATES, "e1")
    assert items == [] and etag == "e1"
    assert route.calls.last.request.headers["if-none-match"] == "e1"


def _xmlrpc_body(value):
    return xmlrpc.client.dumps((value,), methodresponse=True, allow_none=True).encode()


@respx.mock
def test_changelog_since_dedupes_releases_and_tracks_serial(client):
    rows = [
        ["pkg-a", "1.0", 1794734716, "add py3 file pkg_a-1.0-py3-none-any.whl", 101],
        ["pkg-a", "1.0", 1794734718, "add source file pkg-a-1.0.tar.gz", 102],
        ["pkg-b", None, 1794734719, "create", 103],
        ["pkg-b", "0.1", 1794734720, "new release", 104],
        ["pkg-c", "3.0", 1794734721, "remove release", 105],
        ["pkg-d", "1.0", 1794734722, "yank release", 110],
    ]
    route = respx.post(pypi.XMLRPC_URL).respond(content=_xmlrpc_body(rows))
    releases, newest = pypi.changelog_since(client, 100)
    assert [(r.name, r.version, r.serial) for r in releases] == [
        ("pkg-a", "1.0", 101),
        ("pkg-b", "0.1", 104),
    ]
    assert newest == 110
    assert releases[0].published.tzinfo is UTC
    assert b"changelog_since_serial" in route.calls.last.request.content


@respx.mock
def test_last_serial(client):
    respx.post(pypi.XMLRPC_URL).respond(content=_xmlrpc_body(43681404))
    assert pypi.last_serial(client) == 43681404


@respx.mock
def test_fetch_project_and_404(client):
    respx.get("https://pypi.org/pypi/reqeusts/json").respond(json=project())
    assert pypi.fetch_project(client, "reqeusts")["info"]["name"] == "reqeusts"
    respx.get("https://pypi.org/pypi/gone/json").respond(404)
    assert pypi.fetch_project(client, "gone") is None
    assert pypi.fetch_release(client, "gone", "1.0") is None


@respx.mock
def test_fetch_release_merges_version_document_when_project_cache_lags(client):
    stale = project()
    newest = stale["releases"].pop("2.0.1")
    stale["info"]["version"] = "2.0.0"
    respx.get("https://pypi.org/pypi/reqeusts/json").respond(json=stale)
    version_route = respx.get("https://pypi.org/pypi/reqeusts/2.0.1/json").respond(
        json={"info": {"name": "reqeusts", "version": "2.0.1", "summary": "fresh"}, "urls": newest}
    )
    merged = pypi.fetch_release(client, "reqeusts", "2.0.1")
    assert version_route.called
    assert len(merged["releases"]["2.0.1"]) == 3 and merged["info"]["summary"] == "fresh"
    # When the version really does not exist the project is returned unchanged.
    respx.get("https://pypi.org/pypi/reqeusts/9.9/json").respond(404)
    assert "9.9" not in pypi.fetch_release(client, "reqeusts", "9.9")["releases"]


@respx.mock
def test_fetch_release_skips_second_request_when_version_is_present(client):
    respx.get("https://pypi.org/pypi/reqeusts/json").respond(json=project())
    extra = respx.get("https://pypi.org/pypi/reqeusts/2.0.1/json").respond(json={})
    pypi.fetch_release(client, "reqeusts", "2.0.1")
    assert not extra.called


@respx.mock
def test_build_context_prefers_sdist_plus_pure_wheel(client, config, baselines):
    sdist = make_tgz({"reqeusts-2.0.1/setup.py": "from setuptools import setup\nsetup()\n"})
    wheel = make_zip({"reqeusts/__init__.py": "X = 1\n", "evil.pth": "import os\n"})
    respx.get(f"{FILES}/reqeusts-2.0.1.tar.gz").respond(content=sdist)
    respx.get(f"{FILES}/reqeusts-2.0.1-py3-none-any.whl").respond(content=wheel)
    platform = respx.get(f"{FILES}/reqeusts-2.0.1-cp312-cp312-win_amd64.whl").respond(content=b"")
    ctx = pypi.build_context(client, project(), "2.0.1", config, baselines["pypi"], NOW)
    assert ctx.archive_kinds == ["sdist", "wheel:pure"] and not platform.called
    assert set(ctx.files) == {"reqeusts-2.0.1/setup.py", "reqeusts/__init__.py", "evil.pth"}
    assert ctx.repository_url == "https://github.com/x/reqeusts"
    assert ctx.maintainers == ["newbie"]
    assert ctx.description == "HTTP for humans"
    assert ctx.version_count == 2 and ctx.previous_version == "2.0.0"
    assert ctx.size == 1000 and ctx.previous_size == 900
    assert ctx.publisher_is_new is True
    assert ctx.published_at == datetime(2026, 11, 15, 10, 3, tzinfo=UTC)
    assert ctx.package_created_at == datetime(2026, 11, 10, 8, 0, tzinfo=UTC)


def test_build_context_without_files_or_within_budget(client, config, baselines):
    assert pypi.build_context(client, project(), "0.0.1", config, baselines["pypi"], NOW) is None
    huge = project()
    for entry in huge["releases"]["2.0.1"]:
        entry["size"] = 99 * 1024 * 1024
    ctx = pypi.build_context(client, huge, "2.0.1", config, baselines["pypi"], NOW)
    assert ctx.archive_error.startswith("skipped: no downloadable file") and not ctx.files


def test_build_context_ignores_files_on_other_hosts(client, config, baselines):
    doc = project()
    for entry in doc["releases"]["2.0.1"]:
        entry["url"] = "https://evil.example.invalid/" + entry["filename"]
    ctx = pypi.build_context(client, doc, "2.0.1", config, baselines["pypi"], NOW)
    assert not ctx.files and ctx.archive_error


def test_old_project_is_not_a_new_publisher_and_platform_wheel_is_labelled(
    client, config, baselines
):
    doc = project()
    doc["releases"]["2.0.0"][0]["upload_time_iso_8601"] = "2020-01-01T00:00:00.000000Z"
    doc["releases"]["2.0.1"] = [doc["releases"]["2.0.1"][1]]
    ctx = pypi.build_context(
        client, doc, "2.0.1", config, baselines["pypi"], NOW, fetch_archive=False
    )
    assert ctx.publisher_is_new is False and ctx.archive_kinds == ["wheel:platform"]


def test_newest_version_and_repo_url_fallbacks():
    assert pypi.newest_version(project()) == "2.0.1"
    assert pypi.newest_version({"releases": {}}) is None
    assert (
        pypi._repo_url({"home_page": "https://gitlab.com/a/b", "project_urls": None})
        == "https://gitlab.com/a/b"
    )
    assert pypi._repo_url({"home_page": "https://example.invalid", "project_urls": {}}) is None


# ---------------------------------------------------------------- baselines


def test_parse_npm_list_extracts_names():
    source = "export const topDownload = [\n  'semver',\n  '@types/node',\n  \"lodash\",\n]\n"
    assert baseline_source.parse_npm_list(source) == ["semver", "@types/node", "lodash"]


@respx.mock
def test_refresh_writes_both_baselines(client, tmp_path):
    rows = [{"download_count": 1, "project": f"pkg-{i}"} for i in range(1200)]
    respx.get(baseline_source.PYPI_URL).respond(json={"rows": rows})
    js = "export const topDownload = [\n" + "".join(f"  'npm-{i}',\n" for i in range(1500)) + "]\n"
    respx.get(baseline_source.NPM_URLS[0]).respond(500)
    respx.get(baseline_source.NPM_URLS[1]).respond(text=js)
    assert baseline_source.refresh(client, tmp_path) == {"pypi": 1200, "npm": 1500}
    doc = read_json(tmp_path / "npm-top.json")
    assert doc["count"] == 1500 and doc["packages"][0] == "npm-0"


@respx.mock
def test_refresh_refuses_suspiciously_small_lists(client, tmp_path):
    respx.get(baseline_source.PYPI_URL).respond(json={"rows": [{"project": "only-one"}]})
    for url in baseline_source.NPM_URLS:
        respx.get(url).respond(text="export const topDownload = ['a']\n")
    with pytest.raises(baseline_source.BaselineError):
        baseline_source.refresh(client, tmp_path)
    assert not list(tmp_path.iterdir())  # the committed snapshot is left untouched
    with pytest.raises(baseline_source.BaselineError):
        baseline_source.write_baseline(tmp_path, "pypi", ["a"], "x")


def test_committed_baselines_are_usable():
    from pkgwatch.baseline import load_baseline

    npm_names, pypi_names = load_baseline("npm"), load_baseline("pypi")
    assert len(npm_names.names) >= 5000 and "lodash" in npm_names
    assert len(pypi_names.names) >= 5000 and "requests" in pypi_names
    assert "Python_Dateutil" in pypi_names  # PEP 503 normalisation
    assert load_baseline("npm", "/nonexistent-dir").names == []


# ---------------------------------------------------------------- state and util


def test_state_round_trip_and_defaults(tmp_path):
    path = tmp_path / "state" / "cursors.json"
    state = load_state(path)
    assert state == empty_state()
    state["npm"]["seq"] = 123
    state["pypi"]["serial"] = 456
    state["recent"] = ["abc"]
    save_state(state, path)
    again = load_state(path)
    assert again["npm"]["seq"] == 123 and again["pypi"]["serial"] == 456
    assert again["pypi"]["etags"] == {} and again["recent"] == ["abc"]


def test_json_helpers(tmp_path):
    path = tmp_path / "a" / "b.json"
    write_json(path, {"b": 1, "a": [1, 2]})
    assert path.read_text(encoding="utf-8").index('"a"') < path.read_text(encoding="utf-8").index(
        '"b"'
    )
    write_json(path, {"x": 1}, compact=True)
    assert path.read_text(encoding="utf-8") == '{"x":1}\n'
    assert read_json(tmp_path / "missing.json", {"d": 1}) == {"d": 1}
    path.write_text("{broken", encoding="utf-8")
    assert read_json(path, 7) == 7


def test_timestamp_helpers():
    assert parse_ts("2026-11-15T10:00:00.123Z") == datetime(
        2026, 11, 15, 10, 0, 0, 123000, tzinfo=UTC
    )
    assert parse_ts("2026-11-15T10:00:00").tzinfo is UTC
    assert parse_ts("nope") is None and parse_ts(None) is None and parse_ts("") is None
    assert iso(datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)) == "2026-01-02T03:04:05Z"
