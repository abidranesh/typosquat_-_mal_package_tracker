"""Name and metadata detectors: a true positive, a true negative and a near miss each."""

from datetime import timedelta

import pytest

from pkgwatch.baseline import Baseline, canon_glyphs, normalize, squash
from pkgwatch.detectors import metadata, names
from pkgwatch.util import utcnow

# ---------------------------------------------------------------- typosquat


@pytest.mark.parametrize(
    ("ecosystem", "name", "target", "detail"),
    [
        ("pypi", "reqeusts", "requests", "swapped"),
        ("pypi", "requestss", "requests", "doubled"),
        ("pypi", "reqests", "requests", "missing"),
        ("pypi", "colourama", "colorama", "extra"),
        ("npm", "lodahs", "lodash", "swapped"),
        ("npm", "expross", "express", "substituted"),
    ],
)
def test_typosquat_true_positives(make_ctx, ecosystem, name, target, detail):
    (finding,) = names.detect_typosquat(make_ctx(ecosystem, name))
    assert finding.id == "typosquat" and finding.target == target
    assert finding.weight == 25 and detail in finding.message


def test_typosquat_distance_two_weighs_less(make_ctx):
    (finding,) = names.detect_typosquat(make_ctx("pypi", "reqeustz"))
    assert finding.target == "requests" and finding.weight == 12
    assert "2 edit(s)" in finding.message


@pytest.mark.parametrize(
    ("ecosystem", "name"),
    [
        ("pypi", "requests"),  # the popular package itself
        ("pypi", "Requests"),  # same project after normalisation
        ("npm", "zebra-crossing-timer"),  # unrelated
        ("npm", "@example-org/lodahs"),  # scoped names are not compared to unscoped ones
        ("npm", "abc"),  # too short to judge
    ],
)
def test_typosquat_true_negatives(make_ctx, ecosystem, name):
    assert names.detect_typosquat(make_ctx(ecosystem, name)) == []


@pytest.mark.parametrize(
    ("ecosystem", "name", "why"),
    [
        ("pypi", "pandas2", "version suffix on a popular name"),
        ("pypi", "requests2", "allowlisted sibling"),
        ("npm", "chulkz", "two edits from a five-letter name"),
        ("npm", "reactor", "two edits from a five-letter name"),
    ],
)
def test_typosquat_near_misses_do_not_fire(make_ctx, ecosystem, name, why):
    assert names.detect_typosquat(make_ctx(ecosystem, name)) == [], why


def test_short_names_match_at_distance_one_with_a_low_weight(make_ctx):
    (finding,) = names.detect_typosquat(make_ctx("npm", "chalx"))
    assert finding.target == "chalk" and finding.weight == 12


def test_established_packages_get_half_weight(make_ctx):
    old = make_ctx("pypi", "reqeusts", package_created_at=utcnow() - timedelta(days=400))
    (finding,) = names.detect_typosquat(old)
    assert finding.weight == 12 and finding.severity == "low"


# ---------------------------------------------------------------- manipulation


@pytest.mark.parametrize(
    ("ecosystem", "name", "target", "weight"),
    [
        ("pypi", "nurnpy", "numpy", 30),  # rn for m
        ("pypi", "c1ick", "click", 30),  # 1 for l
        ("pypi", "b0t03", "boto3", 30),  # 0 for o
        ("npm", "cross_env", "cross-env", 20),
        ("pypi", "pythondateutil", "python-dateutil", 20),
        ("pypi", "python-requests", "requests", 12),
        ("npm", "lodash-js", "lodash", 12),
        ("npm", "types-node", "@types/node", 25),
        ("npm", "babel-core", "@babel/core", 25),
        ("npm", "preset-env", "@babel/preset-env", 25),
        ("npm", "@babe1/core", "@babel/core", 25),
        ("npm", "@typs/whatever", "@types", 25),
    ],
)
def test_name_manipulation_true_positives(make_ctx, ecosystem, name, target, weight):
    findings = names.detect_name_manipulation(make_ctx(ecosystem, name))
    if target is None:
        assert findings == []  # "b0t03" canonicalises to "boto3", which is not in this baseline
        return
    (finding,) = findings
    assert finding.id == "name-manipulation"
    assert (finding.target, finding.weight) == (target, weight)


@pytest.mark.parametrize(
    ("ecosystem", "name"),
    [
        ("pypi", "python-dateutil"),  # popular itself
        ("npm", "@types/node"),  # popular scoped package itself
        ("npm", "@babel/new-plugin"),  # new package inside a popular scope
        ("npm", "@example-org/lodash"),  # fork under the publisher's own scope
        ("npm", "zebra-crossing-timer"),
        ("pypi", "python-zzzunknown"),  # prefix on a name that is not popular
        ("npm", "ab"),
    ],
)
def test_name_manipulation_negatives_and_near_misses(make_ctx, ecosystem, name):
    assert names.detect_name_manipulation(make_ctx(ecosystem, name)) == []


def test_typosquat_defers_to_manipulation_so_weights_do_not_stack(make_ctx):
    ctx = make_ctx("pypi", "nurnpy")  # homoglyph of numpy and also two edits away
    assert names.detect_typosquat(ctx) == []
    assert len(names.detect_name_manipulation(ctx)) == 1


# ---------------------------------------------------------------- combosquat


def test_combosquat_true_positives(make_ctx):
    (finding,) = names.detect_combosquat(make_ctx("npm", "lodash-helper"))
    assert finding.id == "combosquat" and finding.target == "lodash" and finding.weight == 12
    (finding,) = names.detect_combosquat(make_ctx("npm", "easy-ua-parser-js-toolkit"))
    assert finding.target == "ua-parser-js"
    (finding,) = names.detect_combosquat(make_ctx("pypi", "requests_toolkit"))
    assert finding.target == "requests"


@pytest.mark.parametrize(
    "name",
    [
        "lodash",  # popular itself
        "lodash-zebra",  # extra word is not generic
        "helper-tools",  # generic words but no popular name
        "@example-org/lodash-helper",  # scoped
        "lodashhelper",  # one token: handled by other detectors, not this one
    ],
)
def test_combosquat_negatives_and_near_misses(make_ctx, name):
    assert names.detect_combosquat(make_ctx("npm", name)) == []


def test_combosquat_defers_to_stronger_name_matches(make_ctx):
    assert names.detect_combosquat(make_ctx("npm", "lodash-js")) == []  # affix match instead


# ---------------------------------------------------------------- dependency confusion


def test_dependency_confusion_internal_name_with_high_version(make_ctx):
    ctx = make_ctx("npm", "acme-internal-utils", "99.9.9", version_count=1)
    (finding,) = names.detect_dependency_confusion(ctx)
    assert finding.id == "dependency-confusion"
    assert finding.severity == "high" and finding.weight == 35
    scoped = make_ctx("npm", "@acme/billing-private", "100.0.0", version_count=2)
    assert names.detect_dependency_confusion(scoped)[0].weight == 35


def test_high_first_version_alone_is_a_weak_signal(make_ctx):
    (finding,) = names.detect_dependency_confusion(
        make_ctx("pypi", "newthing", "99.0.0", version_count=1)
    )
    assert finding.severity == "low" and finding.weight == 15


@pytest.mark.parametrize(
    ("name", "version", "count", "why"),
    [
        ("acme-internal-utils", "1.0.0", 1, "internal-looking name at a normal version"),
        ("tide-tables-nl", "2026.11.1", 1, "calendar versioning"),
        ("newthing", "99.0.0", 4, "not a first publish"),
        ("acme-internal-utils", "99.0.0", 40, "long release history"),
        ("requests", "99.0.0", 1, "popular package"),
        ("weird", "not-a-version", 1, "unparseable version"),
    ],
)
def test_dependency_confusion_near_misses(make_ctx, name, version, count, why):
    ctx = make_ctx("pypi", name, version, version_count=count)
    assert names.detect_dependency_confusion(ctx) == [], why


# ---------------------------------------------------------------- metadata


def test_new_publisher_with_similar_name(make_ctx):
    (finding,) = metadata.detect_new_publisher(make_ctx("pypi", "reqeusts", publisher_is_new=True))
    assert finding.id == "new-publisher-similar-name"
    assert finding.target == "requests" and finding.weight == 20


@pytest.mark.parametrize(
    ("name", "is_new", "why"),
    [
        ("reqeusts", False, "established publisher"),
        ("reqeusts", None, "publisher history unknown"),
        ("zebra-crossing-timer", True, "new publisher, unrelated name (near miss)"),
        ("requests", True, "the popular package itself"),
    ],
)
def test_new_publisher_negatives(make_ctx, name, is_new, why):
    assert metadata.detect_new_publisher(make_ctx("pypi", name, publisher_is_new=is_new)) == [], why


def test_sparse_metadata_counts_each_missing_piece(make_ctx):
    ctx = make_ctx("npm", "thing", description="", readme=None, repository_url=None)
    (finding,) = metadata.detect_sparse_metadata(ctx)
    assert finding.id == "sparse-metadata" and finding.weight == 12 and finding.severity == "info"
    assert "description" in finding.message and "repository URL" in finding.message
    placeholder = make_ctx(
        "pypi", "thing", description="UNKNOWN", readme="ERROR: No README data found!"
    )
    assert metadata.detect_sparse_metadata(placeholder)[0].weight == 8


def test_sparse_metadata_negatives(make_ctx):
    assert metadata.detect_sparse_metadata(make_ctx("npm", "thing")) == []
    # Near miss: a popular package is not judged on thin metadata.
    bare = make_ctx("npm", "lodash", description="", readme="", repository_url=None)
    assert metadata.detect_sparse_metadata(bare) == []


def test_repo_impersonation(make_ctx):
    ctx = make_ctx("npm", "expres", repository_url="https://github.com/expressjs/express")
    (finding,) = metadata.detect_repo_impersonation(ctx)
    assert finding.id == "repo-impersonation" and finding.target == "express"
    assert finding.weight == 25


@pytest.mark.parametrize(
    ("name", "repo", "why"),
    [
        ("expres", "https://github.com/someone/expres", "its own repository"),
        ("expres", None, "no repository"),
        ("express", "https://github.com/expressjs/express", "the real package"),
        ("zebra-crossing-timer", "https://github.com/expressjs/express", "unrelated name"),
        ("lodash-helper", "https://github.com/lodash/lodash", "plugins often link the parent repo"),
    ],
)
def test_repo_impersonation_negatives_and_near_misses(make_ctx, name, repo, why):
    assert metadata.detect_repo_impersonation(make_ctx("npm", name, repository_url=repo)) == [], why


def test_popular_package_change_new_maintainer_size_and_version(make_ctx):
    ctx = make_ctx(
        "npm",
        "event-stream",
        "9.0.0",
        maintainers=["old", "new-person"],
        previous_maintainers=["old"],
        previous_version="3.3.5",
        size=900_000,
        previous_size=100_000,
    )
    findings = metadata.detect_popular_change(ctx)
    assert {f.id for f in findings} == {"popular-package-change"}
    assert sorted(f.weight for f in findings) == [10, 10, 15]
    text = " ".join(f.message for f in findings)
    assert "new-person" in text and "9.0x" in text and "3.3.5 to 9.0.0" in text


def test_popular_package_change_negatives_and_near_misses(make_ctx):
    steady = make_ctx(
        "npm",
        "lodash",
        "4.17.22",
        maintainers=["a"],
        previous_maintainers=["a", "b"],  # a maintainer leaving is not flagged
        previous_version="4.17.21",
        size=1_100_000,
        previous_size=1_000_000,
    )
    assert metadata.detect_popular_change(steady) == []
    # Same changes on a package that is not popular: out of scope for this detector.
    unknown = make_ctx(
        "npm", "zebra", "9.0.0", maintainers=["x", "y"], previous_maintainers=["x"],
        previous_version="1.0.0",
    )  # fmt: skip
    assert metadata.detect_popular_change(unknown) == []
    # A tiny package tripling in size is below the absolute threshold.
    small = make_ctx(
        "npm", "lodash", "4.17.22", previous_version="4.17.21", size=3000, previous_size=900
    )
    assert metadata.detect_popular_change(small) == []
    assert metadata.detect_popular_change(make_ctx("npm", "lodash")) == []  # first release


# ---------------------------------------------------------------- helpers


def test_normalisation_helpers():
    assert normalize("Python_Dateutil", "pypi") == "python-dateutil"
    assert normalize("Cross_Env", "npm") == "cross_env"
    assert squash("python-date.util") == "pythondateutil"
    assert canon_glyphs("nurnpy") == "numpy" and canon_glyphs("l0dash") == "lodash"


def test_baseline_indexes():
    baseline = Baseline("npm", ["Lodash", "lodash", "@types/node", "@babel/preset-env", "ab"])
    assert baseline.names[0] == "lodash" and len(baseline.names) == 4
    assert "LODASH" in baseline and "nope" not in baseline
    assert baseline.scopes == {"types": ["node"], "babel": ["preset-env"]}
    assert baseline.scope_lookalikes["types-node"] == "@types/node"
    assert baseline.scope_lookalikes["preset-env"] == "@babel/preset-env"
    assert "node" not in baseline.scope_lookalikes  # too short to count as a copy
    assert baseline.typo_pool(10) == ["lodash"]
    assert baseline.top(1) == ["lodash"]


def test_best_match_prefers_the_strongest_signal(config, baselines):
    match = names.best_match("nurnpy", "pypi", baselines["pypi"], config)
    assert (match.kind, match.target) == ("homoglyph", "numpy")
    assert names.best_match("lodash-helper", "npm", baselines["npm"], config).kind == "combosquat"
    assert names.best_match("zebra-crossing-timer", "npm", baselines["npm"], config) is None
