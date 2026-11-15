"""Cursor persistence (``state/cursors.json``)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .util import read_json, write_json

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "state" / "cursors.json"


def empty_state() -> dict[str, Any]:
    return {"npm": {"seq": None}, "pypi": {"serial": None, "etags": {}}, "issue_backlog": []}


def load_state(path: Path | str = DEFAULT_PATH) -> dict[str, Any]:
    state = empty_state()
    loaded = read_json(path, {})
    if isinstance(loaded, dict):
        for key, value in loaded.items():
            if isinstance(value, dict) and isinstance(state.get(key), dict):
                state[key].update(value)
            else:
                state[key] = value
    return state


def save_state(state: dict[str, Any], path: Path | str = DEFAULT_PATH) -> None:
    write_json(path, state)
