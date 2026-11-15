"""Binary and dropper detectors: unexpected executables, download-and-run code,
and archives that could not be read safely."""

from __future__ import annotations

import re

from ..context import Evidence, Finding, PackageContext

_EXECUTABLE_EXT = (".exe", ".scr", ".msi", ".com")
_LIBRARY_EXT = (".dll", ".so", ".dylib", ".pyd", ".node")
_MACHO = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
# Launcher stubs that setuptools and distlib legitimately ship.
_KNOWN_STUBS = re.compile(r"^(cli|gui|t|w)(-?(32|64))?(-arm(64)?)?\.exe$")
_NATIVE_NAME = re.compile(r"(win32|windows|linux|darwin|macos|android|x64|x86|arm64|musl|gnu)")
_NATIVE_PATH = re.compile(r"(^|/)(prebuilds?|build/Release|bin/(win|linux|darwin|mac)\w*|native)/")

_DOWNLOAD = re.compile(
    r"""(
        \burlretrieve\s*\( | \burlopen\s*\( | \brequests\.get\s*\( | \bhttpx\.(get|stream)\s*\( |
        \bhttps?\.get\s*\( | (?<![.\w$])fetch\s*\(\s*["'`\w] | \baxios(\.get)?\s*\( |
        \b(curl|wget)\b[^\n|;&]{0,200}https?:// | \bInvoke-WebRequest\b | \bDownloadFile\s*\( |
        \bbitsadmin\b | \bcertutil\s+-urlcache
    )""",
    re.VERBOSE,
)
_RUN = re.compile(
    r"""(
        \bchmod\s*\(\s*[^,\n]+,\s*(0o?)?7[0-7]{2} | \bchmod\s+(\+x|7[0-7]{2}) | \bchmodSync\s*\( |
        \b(execFile|execFileSync|spawn|spawnSync|execSync)\s*\( | \bos\.startfile\s*\( |
        \bsubprocess\.(Popen|run|call|check_call|check_output)\s*\( | \bos\.system\s*\( |
        \bStart-Process\b | \bos\.exec\w+\s*\( | \|\s*(sudo\s+(-\w+\s+)*)?(ba|z)?sh\b
    )""",
    re.VERBOSE,
)
# A runnable file named in a string literal, or a download piped straight into a shell.
_ARTIFACT = re.compile(
    r"""(
        \.(exe|dll|scr|msi|bin|elf|ps1|bat|vbs|sh)["'`] | \|\s*(sudo\s+(-\w+\s+)*)?(ba|z)?sh\b
    )""",
    re.VERBOSE | re.IGNORECASE,
)
WINDOW_BEFORE = 300
WINDOW_AFTER = 1200


def binary_kind(data: bytes) -> str | None:
    """Identify native executables by their magic bytes."""
    if data[:2] == b"MZ" and len(data) >= 64:
        return "Windows PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] in _MACHO:
        return "Mach-O"
    return None


def _expects_native(ctx: PackageContext) -> bool:
    """Whether this package plausibly ships compiled code on purpose."""
    if "wheel:platform" in ctx.archive_kinds:
        return True
    if ctx.ecosystem != "npm":
        return False
    manifest = ctx.package_json
    if manifest.get("os") or manifest.get("cpu") or manifest.get("gypfile"):
        return True
    if _NATIVE_NAME.search(ctx.name.lower()):
        return True
    return any(p.endswith("binding.gyp") or _NATIVE_PATH.search(p) for p in ctx.file_sizes)


def detect_binaries(ctx: PackageContext) -> list[Finding]:
    native_ok = _expects_native(ctx)
    flagged = []
    for path in sorted(ctx.files):
        lower = path.lower()
        base = lower.rsplit("/", 1)[-1]
        kind = binary_kind(ctx.files[path])
        executable = lower.endswith(_EXECUTABLE_EXT) or kind == "Windows PE"
        library = lower.endswith(_LIBRARY_EXT) or kind in ("ELF", "Mach-O")
        if _KNOWN_STUBS.match(base) or not (executable or library):
            continue
        if lower.endswith(".node"):  # Node native addons are binaries by definition
            continue
        if native_ok:
            continue
        flagged.append((path, kind or "binary by extension"))
    if not flagged:
        return []
    listing = ", ".join(f"{p} ({k})" for p, k in flagged[:3])
    more = f" and {len(flagged) - 3} more" if len(flagged) > 3 else ""
    return [
        Finding(
            "binary-dropper",
            "medium",
            ctx.config.weight("unexpected_binary"),
            "Compiled executable or library in a package that is not declared as native.",
            Evidence(flagged[0][0], listing + more),
        )
    ]


def detect_download_execute(ctx: PackageContext) -> list[Finding]:
    """A download followed closely by making a file executable or running it."""
    for path, text in ctx.scan_code.items():
        if re.search(r"(^|/)(tests?|__tests__|examples?|docs?)/", path):
            continue
        for download in _DOWNLOAD.finditer(text):
            run = _RUN.search(text, download.start(), download.end() + WINDOW_AFTER)
            if not run:
                continue
            # The runnable file must be named between the download and the run.
            if not _ARTIFACT.search(text, max(0, download.start() - WINDOW_BEFORE), run.end()):
                continue
            start = text.rfind("\n", 0, download.start()) + 1
            end = text.find("\n", download.start())
            return [
                Finding(
                    "binary-dropper",
                    "medium",
                    ctx.config.weight("download_and_execute"),
                    "Code downloads a file and then executes it or marks it executable.",
                    Evidence(path, text[start : end if end != -1 else len(text)]),
                )
            ]
    return []


def detect_unsafe_archive(ctx: PackageContext) -> list[Finding]:
    """The archive itself tried to escape its root (zip-slip style entry names)."""
    if not (ctx.archive_error or "").startswith("unsafe:"):
        return []
    return [
        Finding(
            "unsafe-archive",
            "high",
            ctx.config.weight("unsafe_archive"),
            "Archive contains absolute or parent-directory paths and was not unpacked.",
            Evidence("(archive)", ctx.archive_error or ""),
        )
    ]


DETECTORS = (detect_binaries, detect_download_execute, detect_unsafe_archive)
