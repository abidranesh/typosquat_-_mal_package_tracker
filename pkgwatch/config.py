"""Configuration loading. All tunables live in ``config.toml`` next to this file."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_PATH = Path(__file__).with_name("config.toml")


@dataclass(frozen=True)
class Config:
    """Read-only view over the parsed TOML document."""

    raw: dict[str, Any] = field(default_factory=dict)

    def section(self, name: str) -> dict[str, Any]:
        return self.raw.get(name, {})

    @property
    def project(self) -> dict[str, Any]:
        return self.section("project")

    @property
    def limits(self) -> dict[str, Any]:
        return self.section("limits")

    @property
    def thresholds(self) -> dict[str, int]:
        return self.section("thresholds")

    @property
    def output(self) -> dict[str, Any]:
        return self.section("output")

    @property
    def names(self) -> dict[str, Any]:
        return self.section("names")

    @property
    def weights(self) -> dict[str, int]:
        return self.section("weights")

    def weight(self, key: str) -> int:
        return int(self.weights[key])

    @property
    def repo(self) -> str:
        return str(self.project["repo"])

    @property
    def user_agent(self) -> str:
        return str(self.project["user_agent"])


def load_config(path: Path | str | None = None) -> Config:
    with open(path or DEFAULT_PATH, "rb") as fh:
        return Config(tomllib.load(fh))
