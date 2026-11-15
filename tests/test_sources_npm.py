from datetime import UTC, datetime

import respx

from pkgwatch.sources import npm
from pkgwatch.sources.common import clean_repo_url, host_allowed, is_repo_host
from tests.helpers import make_tgz

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
TARBALL = "https://registry.npmjs.org/lodahs/-/lodahs-1.0.1.tgz"


def packument(**overrides):
    doc = {
        "_id": "lodahs",
        "name": "lodahs",
        "description": "utilities",
        "readme": "ERROR: No README data found!",
        "maintainers": [{"name": "newbie", "email": "n@example.invalid"}],
        "time": {
            "created": "2026-11-14T10:00:00.000Z",
            "modified": "2026-11-15T11:00:00.000Z",
            "1.0.0": "2026-11-14T10:00:01.000Z",
            "1.0.1": "2026-11-15T11:00:00.000Z",
        },
        "versions": {
            "1.0.0": {
                "name": "lodahs",
                "version": "1.0.0",
                "maintainers": [{"name": "newbie"}],
                "dist": {"tarball": "https://registry.npmjs.org/lodahs/-/lodahs-1.0.0.tgz"},
            },
            "1.0.1": {
                "name": "lodahs",
                "version": "1.0.1",
                "description": "utilities",
                "scripts": {"postinstall": "node index.js"},
                "repository": {"type": "git", "url": "git+https://github.com/x/lodahs.git"},
                "maintainers": [{"name": "newbie"}, {"name": "second"}],
                "_npmUser": {"name": "newbie"},
                "dist": {"tarball": TARBALL, "unpackedSize": 1234},
            },
        },
    }
    doc.update(overrides)
    return doc


@respx.mock
def test_fetch_changes_parses_rows_and_resume_point(client):
    route = respx.get(npm.CHANGES_URL).respond(
        json={
            "results": [
                {"seq": 11, "id": "a", "changes": [{"rev": "1-x"}]},
                {"seq": 13, "id": "@s/b", "changes": [{"rev": "2-y"}], "deleted": True},
                {"seq": 14, "id": "_design/app", "changes": []},
            ],
            "last_seq": 14,
        }
    )
    changes, last = npm.fetch_changes(client, 10, 500)
    assert [(c.seq, c.name, c.deleted) for c in changes] == [(11, "a", False), (13, "@s/b", True)]
    assert last == 14
    assert dict(route.calls.last.request.url.params) == {"since": "10", "limit": "500"}


@respx.mock
def test_fetch_changes_with_no_results_keeps_cursor(client):
    respx.get(npm.CHANGES_URL).respond(json={"results": [], "last_seq": 10})
    assert npm.fetch_changes(client, 10, 5) == ([], 10)


@respx.mock
def test_latest_changes_returns_oldest_first(client):
    route = respx.get(npm.CHANGES_URL).respond(
        json={"results": [{"seq": 9, "id": "b"}, {"seq": 7, "id": "a"}], "last_seq": 7}
    )
    assert [c.name for c in npm.latest_changes(client, 2)] == ["a", "b"]
    assert route.calls.last.request.url.params["descending"] == "true"


@respx.mock
def test_current_seq(client):
    respx.get(npm.REPLICATE_ROOT).respond(json={"db_name": "registry", "update_seq": 4242})
    assert npm.current_seq(client) == 4242


@respx.mock
def test_fetch_packument_encodes_scoped_names_and_handles_404(client):
    route = respx.get("https://registry.npmjs.org/@scope%2Fname").respond(
        json={"name": "@scope/name"}
    )
    assert npm.fetch_packument(client, "@scope/name") == {"name": "@scope/name"}
    assert route.called
    respx.get("https://registry.npmjs.org/gone").respond(404)
    assert npm.fetch_packument(client, "gone") is None


def test_select_version_picks_newest_recent_release():
    assert npm.select_version(packument(), NOW, 48) == "1.0.1"
    assert npm.select_version(packument(), datetime(2026, 12, 1, tzinfo=UTC), 48) is None
    assert npm.select_version({"versions": {}, "time": {}}, NOW, 48) is None
    # A time entry without a matching version document (unpublished) is ignored.
    doc = packument()
    del doc["versions"]["1.0.1"]
    assert npm.select_version(doc, NOW, 48) == "1.0.0"


@respx.mock
def test_build_context_reads_metadata_and_archive(client, config, baselines):
    files = {"package/package.json": '{"name":"lodahs"}', "package/index.js": "module.exports = 1"}
    respx.get(TARBALL).respond(content=make_tgz(files))
    respx.get(npm.SEARCH_URL).respond(json={"total": 1, "objects": []})
    ctx = npm.build_context(client, packument(), "1.0.1", config, baselines["npm"], NOW)
    assert (ctx.ecosystem, ctx.name, ctx.version) == ("npm", "lodahs", "1.0.1")
    assert ctx.repository_url == "https://github.com/x/lodahs"
    assert ctx.maintainers == ["newbie", "second"]
    assert ctx.previous_maintainers == ["newbie"]
    assert ctx.previous_version == "1.0.0" and ctx.version_count == 2
    assert ctx.size == 1234 and not ctx.is_first_release
    assert ctx.published_at == datetime(2026, 11, 15, 11, 0, tzinfo=UTC)
    assert ctx.files["package/index.js"] == b"module.exports = 1"
    assert ctx.manifest["scripts"] == {"postinstall": "node index.js"}
    assert "_npmUser" not in ctx.manifest
    assert ctx.publisher_is_new is True  # similar name, new package, one package on record
    assert ctx.archive_error is None


@respx.mock
def test_publisher_with_history_is_not_new(client, config, baselines):
    respx.get(TARBALL).respond(content=make_tgz({"package/index.js": "1"}))
    respx.get(npm.SEARCH_URL).respond(json={"total": 40})
    ctx = npm.build_context(client, packument(), "1.0.1", config, baselines["npm"], NOW)
    assert ctx.publisher_is_new is False


@respx.mock
def test_publisher_lookup_is_skipped_for_unrelated_names_and_old_packages(
    client, config, baselines
):
    search = respx.get(npm.SEARCH_URL).respond(json={"total": 1})
    doc = packument(name="zebra-crossing-timer")
    ctx = npm.build_context(
        client, doc, "1.0.1", config, baselines["npm"], NOW, fetch_archive=False
    )
    assert ctx.publisher_is_new is None and not search.called
    old = packument()
    old["time"]["created"] = "2020-01-01T00:00:00.000Z"
    ctx = npm.build_context(
        client, old, "1.0.1", config, baselines["npm"], NOW, fetch_archive=False
    )
    assert ctx.publisher_is_new is False and not search.called


@respx.mock
def test_publisher_count_failure_is_unknown(client):
    respx.get(npm.SEARCH_URL).respond(500)
    assert npm.publisher_package_count(client, "someone") is None


@respx.mock
def test_tarball_on_foreign_host_is_not_downloaded(client, config, baselines):
    doc = packument(name="zebra-crossing-timer")
    doc["versions"]["1.0.1"]["dist"]["tarball"] = "https://evil.example.invalid/x.tgz"
    ctx = npm.build_context(client, doc, "1.0.1", config, baselines["npm"], NOW)
    assert "not hosted on the npm registry" in ctx.archive_error and not ctx.files


@respx.mock
def test_oversized_and_unsafe_archives_are_recorded_not_raised(client, config, baselines):
    doc = packument(name="zebra-crossing-timer")
    doc["versions"]["1.0.1"]["dist"]["unpackedSize"] = 10**9
    ctx = npm.build_context(client, doc, "1.0.1", config, baselines["npm"], NOW)
    assert ctx.archive_error.startswith("skipped: unpacked size")

    doc = packument(name="zebra-crossing-timer")
    respx.get(TARBALL).respond(content=make_tgz({"package/../../escape.js": "x"}))
    ctx = npm.build_context(client, doc, "1.0.1", config, baselines["npm"], NOW)
    assert ctx.archive_error.startswith("unsafe:") and not ctx.files

    respx.get(TARBALL).respond(content=b"not a tarball")
    ctx = npm.build_context(client, doc, "1.0.1", config, baselines["npm"], NOW)
    assert ctx.archive_error.startswith("skipped:")

    respx.get(TARBALL).respond(200, content=b"x" * (11 * 1024 * 1024))
    ctx = npm.build_context(client, doc, "1.0.1", config, baselines["npm"], NOW)
    assert "larger than the download limit" in ctx.archive_error

    respx.get(TARBALL).respond(403)
    ctx = npm.build_context(client, doc, "1.0.1", config, baselines["npm"], NOW)
    assert "download failed" in ctx.archive_error


def test_clean_repo_url_normalises_common_spellings():
    assert clean_repo_url({"url": "git+https://github.com/a/b.git"}) == "https://github.com/a/b"
    assert clean_repo_url("git@github.com:a/b.git") == "https://github.com/a/b"
    assert clean_repo_url("github:a/b") == "https://github.com/a/b"
    assert clean_repo_url("a/b") == "https://github.com/a/b"
    assert clean_repo_url("git://gitlab.com/a/b.git#main") == "https://gitlab.com/a/b"
    assert clean_repo_url("") is None and clean_repo_url(None) is None
    assert clean_repo_url("ftp://x/y") is None


def test_host_checks():
    assert host_allowed("https://registry.npmjs.org/a/-/a-1.tgz", npm.TARBALL_HOSTS)
    assert not host_allowed("http://registry.npmjs.org/a/-/a-1.tgz", npm.TARBALL_HOSTS)
    assert not host_allowed("https://registry.npmjs.org.evil.example/a.tgz", npm.TARBALL_HOSTS)
    assert is_repo_host("https://github.com/a/b") and not is_repo_host("https://example.com/a")
    assert not is_repo_host(None)
