"""Sanity checks for the static dashboard and the workflows (standard library only).

Run by CI as ``python scripts/check_site.py``. It verifies that:

* ``docs/index.html`` is well-formed enough (balanced tags, unique ids, a title, a
  language), that every element id the script looks up exists, and that the page loads
  nothing from another origin;
* the committed data files parse and have the shape the dashboard expects;
* the public pages use neutral wording;
* each workflow file has the triggers, permissions and paths this project relies on.
"""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
WORKFLOWS = ROOT / ".github" / "workflows"
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"}
SVG_VOID = {"path", "circle", "rect", "line"}
BANNED_WORDS = ("malware", "malicious")


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.errors: list[str] = []
        self.ids: list[str] = []
        self.resources: list[str] = []
        self.tags: set[str] = set()
        self.lang: str | None = None
        self.text: list[str] = []
        self.inline_scripts = 0
        self.labelled_inputs: set[str] = set()
        self.inputs: list[str] = []
        self._label_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        self.tags.add(tag)
        if "id" in values:
            self.ids.append(values["id"] or "")
        if tag == "html":
            self.lang = values.get("lang")
        if tag in ("script", "img", "iframe", "source") and values.get("src"):
            self.resources.append(values["src"] or "")
        if tag == "script" and not values.get("src"):
            self.inline_scripts += 1
        if tag == "link" and values.get("rel") in ("stylesheet", "icon", "preload"):
            self.resources.append(values.get("href") or "")
        if tag == "label":
            self._label_depth += 1
        if tag in ("input", "select", "textarea"):
            self.inputs.append(values.get("id") or "")
            if self._label_depth and values.get("id"):
                self.labelled_inputs.add(values["id"] or "")
        for name in values:
            if name.startswith("on"):
                self.errors.append(f"inline event handler {name} on <{tag}>")
        if tag not in VOID and tag not in SVG_VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in VOID and tag not in SVG_VOID:
            self.stack.pop()

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID or tag in SVG_VOID:
            return
        if tag == "label":
            self._label_depth -= 1
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}> (open: {self.stack[-3:]})")
            if tag in self.stack:
                while self.stack and self.stack.pop() != tag:
                    pass
            return
        self.stack.pop()

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def check_html(errors: list[str]) -> None:
    page = DOCS / "index.html"
    source = page.read_text(encoding="utf-8")
    parser = PageParser()
    parser.feed(source)
    parser.close()
    errors.extend(f"index.html: {e}" for e in parser.errors)
    if parser.stack:
        errors.append(f"index.html: unclosed tags {parser.stack}")
    if not source.lstrip().lower().startswith("<!doctype html>"):
        errors.append("index.html: missing <!doctype html>")
    if parser.lang != "en":
        errors.append('index.html: <html> needs lang="en"')
    for tag in ("title", "header", "nav", "main", "footer", "h1", "table"):
        if tag not in parser.tags:
            errors.append(f"index.html: missing <{tag}>")
    duplicates = {i for i in parser.ids if parser.ids.count(i) > 1}
    if duplicates:
        errors.append(f"index.html: duplicate ids {sorted(duplicates)}")
    if parser.inline_scripts:
        errors.append("index.html: inline <script> blocks are not allowed")
    for resource in parser.resources:
        if re.match(r"^(https?:)?//", resource):
            errors.append(f"index.html: external resource {resource} (no CDN dependencies allowed)")
        elif not (DOCS / resource).exists():
            errors.append(f"index.html: missing local resource {resource}")
    for field in parser.inputs:
        if field not in parser.labelled_inputs:
            errors.append(f"index.html: form control '{field}' has no label")
    if "Report a false positive" not in " ".join(parser.text):
        errors.append("index.html: missing the false-positive link text")

    script = (DOCS / "assets" / "app.js").read_text(encoding="utf-8")
    style = (DOCS / "assets" / "style.css").read_text(encoding="utf-8")
    ids = set(parser.ids)
    wanted = set(re.findall(r'\$\("([\w-]+)"\)', script))
    for prefix, suffixes in re.findall(r'\$\("([\w-]+-)" \+ \w+ \+ "(-[\w]+)"\)', script):
        wanted.discard(prefix)
        for field in ("scanned", "flagged", "high"):
            wanted.add(f"{prefix}{field}{suffixes}")
    wanted |= {f"view-{name}" for name in ("findings", "detail", "about")}
    for missing in sorted(i for i in wanted if i not in ids and not i.endswith("-")):
        errors.append(f"app.js looks up #{missing}, which index.html does not define")
    for name, text in (("app.js", script), ("style.css", style)):
        if re.search(
            r"""(?:src|href|url\(|import)\s*[=(]?\s*["']?(?:https?:)?//(?!github\.com|www\.npmjs\.com|pypi\.org)""",
            text,
        ):
            errors.append(f"{name}: loads a resource from another origin")
    if re.search(r"\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML|document\.write", script):
        errors.append("app.js: registry data must never be inserted as HTML")
    if 'data-theme="dark"' not in source:
        errors.append("index.html: dark mode must be the default theme")
    public = " ".join(parser.text).lower() + script.lower()
    for word in BANNED_WORDS:
        if word in public:
            errors.append(
                f"dashboard uses the word '{word}'; listings must stay neutral ('suspicious')"
            )


def check_data(errors: list[str]) -> None:
    data = DOCS / "data"
    try:
        latest = json.loads((data / "latest.json").read_text(encoding="utf-8"))
        stats = json.loads((data / "stats.json").read_text(encoding="utf-8"))
        index = json.loads((data / "findings" / "index.json").read_text(encoding="utf-8"))
        json.loads((data / "health.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        errors.append(f"docs/data: {exc}")
        return
    required = {
        "key",
        "ecosystem",
        "name",
        "version",
        "score",
        "severity",
        "scanned_at",
        "findings",
    }
    for record in latest.get("findings", []):
        if not required <= set(record):
            errors.append(
                f"latest.json: record {record.get('key')} lacks {sorted(required - set(record))}"
            )
            break
        if record["score"] < 15 or record["severity"] not in ("low", "medium", "high"):
            errors.append(f"latest.json: unlisted record {record['key']} was published")
            break
    if len(latest.get("findings", [])) > 500:
        errors.append("latest.json holds more than 500 findings")
    if not {"totals", "daily", "hourly"} <= set(stats):
        errors.append("stats.json lacks totals/daily/hourly")
    for day in index.get("days", {}):
        year, month, dom = day.split("-")
        if not (data / "findings" / year / month / f"{dom}.json").exists():
            errors.append(f"index.json lists {day}, but its file is missing")
    for feed in ("feed.xml", "feed-high.xml"):
        try:
            root = ET.fromstring((DOCS / feed).read_bytes())
        except (OSError, ET.ParseError) as exc:
            errors.append(f"{feed}: {exc}")
            continue
        if root.tag != "rss" or root.get("version") != "2.0" or root.find("channel") is None:
            errors.append(f"{feed}: not an RSS 2.0 document")
        text = ET.tostring(root, encoding="unicode").lower()
        if any(word in text for word in BANNED_WORDS):
            errors.append(f"{feed}: uses non-neutral wording")


WORKFLOW_RULES: dict[str, list[str]] = {
    "ci.yml": [
        r"^on:", r"pull_request:", r"ruff check", r"ruff format --check", r"--cov-fail-under=85",
        r"python -m pkgwatch\.eval", r"scripts/check_site\.py", r"requirements-dev\.txt",
    ],
    "scan.yml": [
        r'cron: "[^"]+"', r"workflow_dispatch:", r"group: scan", r"cancel-in-progress: false",
        r"timeout-minutes: 20", r"contents: write", r"issues: write", r"python -m pkgwatch\.scan",
        r"cache: pip", r"pkgwatch-bot", r"git diff --cached --quiet", r"for attempt in 1 2 3",
        r"pull --rebase", r"GITHUB_TOKEN: \$\{\{ secrets\.GITHUB_TOKEN \}\}",
    ],
    "baselines.yml": [
        r'cron: "[^"]+"', r"workflow_dispatch:", r"contents: write",
        r"python -m pkgwatch\.sources\.baselines", r"data/baselines",
    ],
    "keepalive.yml": [r'cron: "[^"]+"', r"contents: write", r"state/keepalive"],
}  # fmt: skip
_CRON = re.compile(r'cron: "([^"]+)"')
_PATHS = re.compile(r"(?:python |-r |add (?:-A )?)((?:[\w./-]+ ?)+)")


def check_workflows(errors: list[str]) -> None:
    for name, rules in WORKFLOW_RULES.items():
        path = WORKFLOWS / name
        if not path.exists():
            errors.append(f"{name}: workflow file is missing")
            continue
        text = path.read_text(encoding="utf-8")
        if "\t" in text:
            errors.append(f"{name}: contains tab characters (invalid YAML indentation)")
        for line_number, line in enumerate(text.splitlines(), 1):
            indent = len(line) - len(line.lstrip(" "))
            if line.strip() and not line.lstrip().startswith("#") and indent % 2:
                errors.append(f"{name}:{line_number}: odd indentation")
        for key in ("name:", "on:", "jobs:"):
            if not re.search(rf"^{key}", text, re.M):
                errors.append(f"{name}: missing top-level '{key}'")
        for rule in rules:
            if not re.search(rule, text, re.M):
                errors.append(f"{name}: expected to find /{rule}/")
        for cron in _CRON.findall(text):
            if len(cron.split()) != 5:
                errors.append(f"{name}: cron '{cron}' does not have five fields")
        if re.search(r"secrets\.(?!GITHUB_TOKEN\b)\w+", text):
            errors.append(f"{name}: uses a secret other than GITHUB_TOKEN")
        for match in re.findall(r"(?:scripts|pkgwatch|data|state|docs|reports)/[\w./*-]+", text):
            target = match.rstrip("./")
            if "*" in target or target.endswith(("keepalive",)):
                continue
            if not (ROOT / target).exists():
                errors.append(f"{name}: references {target}, which does not exist")
    scan = (
        (WORKFLOWS / "scan.yml").read_text(encoding="utf-8")
        if (WORKFLOWS / "scan.yml").exists()
        else ""
    )
    minutes = _CRON.search(scan)
    if (
        minutes
        and len(minutes.group(1).split()[0].split(",")) != 3
        and "*/20" not in minutes.group(1)
    ):
        errors.append("scan.yml: the schedule should run every 20 minutes")


def main() -> int:
    errors: list[str] = []
    check_html(errors)
    check_data(errors)
    check_workflows(errors)
    for error in errors:
        print(f"ERROR: {error}")
    print("site and workflow checks: " + ("FAILED" if errors else "ok"))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
