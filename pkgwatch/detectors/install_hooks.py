"""npm install-hook detector: scripts that run automatically on ``npm install``."""

from __future__ import annotations

import re

from ..context import Evidence, Finding, PackageContext

HOOKS = ("preinstall", "install", "postinstall")

# Commands that are routine in install hooks (native builds, git hooks, notices).
_BENIGN = re.compile(
    r"""^(
        node-gyp(\s+(rebuild|configure|build))* | node-gyp-build(-optional-packages)?(\s.*)? |
        prebuild-install(\s.*)? | node-pre-gyp\s+install(\s.*)? | prebuildify(\s.*)? |
        cmake-js(\s.*)? | electron-rebuild(\s.*)? | electron-builder\s+install-app-deps |
        husky(\s+install)? | is-ci\s*\|\|\s*husky(\s+install)? | patch-package | ngcc(\s.*)? |
        (npx\s+)?only-allow\s+\w+ | opencollective(-postinstall)?(\s.*)? |
        (npm|yarn|pnpm)\s+(run\s+)?(build|prepare|compile|bootstrap|generate)(:[\w-]+)? |
        tsc(\s.*)? | lerna\s+bootstrap | prisma\s+generate | nuxt\s+prepare |
        echo(\s.*)? | exit\s+0 | true | :
    )$""",
    re.VERBOSE,
)

_RISKY = re.compile(
    r"""(
        \b(curl|wget|powershell|pwsh|certutil|bitsadmin|mshta|rundll32|ncat|netcat)\b |
        \b(ba|z|da)?sh\s+-c\b | \bcmd(\.exe)?\s+/c\b | \bnc\s+-?\w | /dev/tcp/ |
        \bpython[\d.]*\s+-c\b | \bnode\s+(-e|--eval|-p)\b | \bbase64\s+(-d|--decode)\b |
        \bchmod\s+\+x\b | \bInvoke-(WebRequest|Expression|RestMethod)\b | \b(iwr|iex)\b |
        https?:// | \|\s*(ba|z)?sh\b | \beval\b | >\s*/dev/null\s+2>&1\s*&
    )""",
    re.VERBOSE | re.IGNORECASE,
)

_NODE_FILE = re.compile(r"^node\s+(?!-)(\S+)")
_SPLIT = re.compile(r"\s*(?:&&|\|\||;)\s*")


def _classify(command: str) -> str:
    if _RISKY.search(command):
        return "risky"
    parts = [p for p in _SPLIT.split(command.strip()) if p]
    if parts and all(_BENIGN.match(p) for p in parts):
        return "benign"
    if any(_NODE_FILE.match(p) for p in parts):
        return "node-file"
    return "plain"


def detect_install_hooks(ctx: PackageContext) -> list[Finding]:
    if ctx.ecosystem != "npm":
        return []
    scripts = ctx.package_json.get("scripts")
    if not isinstance(scripts, dict):
        return []
    out = []
    for hook in HOOKS:
        command = scripts.get(hook)
        if not isinstance(command, str) or not command.strip():
            continue
        kind = _classify(command)
        if kind == "benign":
            continue
        evidence = Evidence("package.json", f'"{hook}": "{command}"')
        if kind == "risky":
            out.append(
                Finding(
                    "npm-install-hook",
                    "high",
                    ctx.config.weight("install_hook_risky"),
                    f"'{hook}' script runs a shell, downloader or inline code at install time.",
                    evidence,
                )
            )
        elif kind == "node-file":
            out.append(
                Finding(
                    "npm-install-hook",
                    "medium",
                    ctx.config.weight("install_hook_node_file"),
                    f"'{hook}' script runs a bundled JavaScript file at install time.",
                    evidence,
                )
            )
        else:
            out.append(
                Finding(
                    "npm-install-hook",
                    "low",
                    ctx.config.weight("install_hook_plain"),
                    f"'{hook}' script runs automatically at install time.",
                    evidence,
                )
            )
    return out


DETECTORS = (detect_install_hooks,)
