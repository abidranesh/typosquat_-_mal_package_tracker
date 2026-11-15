"""Shared pytest fixtures."""

from __future__ import annotations

from datetime import timedelta

import pytest

from pkgwatch.config import load_config
from pkgwatch.context import PackageContext
from pkgwatch.fixtures import fixture_baselines
from pkgwatch.http import Client
from pkgwatch.util import utcnow

README = "A documented library with enough README text to count as real documentation. " * 2


@pytest.fixture(scope="session")
def config():
    return load_config()


@pytest.fixture(scope="session")
def baselines():
    return fixture_baselines()


@pytest.fixture
def client(config):
    """An HTTP client that never really sleeps between retries."""
    sleeps: list[float] = []
    with Client(config, sleep=sleeps.append, token="test-token") as http:
        http.sleeps = sleeps
        yield http


@pytest.fixture
def make_ctx(config, baselines):
    """Build a PackageContext with unremarkable metadata unless overridden."""

    def factory(ecosystem="npm", name="example-pkg", version="1.2.3", files=None, **overrides):
        data = {
            path: content.encode("utf-8") if isinstance(content, str) else content
            for path, content in (files or {}).items()
        }
        fields = {
            "description": "A documented utility library",
            "readme": README,
            "repository_url": f"https://github.com/example-org/{name.split('/')[-1]}",
            "maintainers": ["dev"],
            "publisher_is_new": False,
            "version_count": 5,
            "package_created_at": utcnow() - timedelta(days=30),
        }
        fields.update(overrides)
        return PackageContext(
            ecosystem=ecosystem,
            name=name,
            version=version,
            config=config,
            baseline=baselines[ecosystem],
            files=data,
            file_sizes={path: len(content) for path, content in data.items()},
            **fields,
        )

    return factory
