"""Obfuscation detector: hidden payloads, encoded blobs, and unreadable code."""

from __future__ import annotations

import math
import re
from collections import Counter

from ..context import Evidence, Finding, PackageContext

_OBFUSCATED_EXEC = re.compile(
    r"""(
        \beval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode|Buffer\.from)\s*\( |
        \bnew\s+Function\s*\(\s*(atob|unescape|Buffer\.from|String\.fromCharCode)\s*\( |
        \beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\) |
        \b(exec|eval)\s*\(\s*(zlib|lzma|bz2|gzip)\.decompress\s*\( |
        \b(exec|eval)\s*\(\s*(base64\.\w*decode\w*|bytes\.fromhex|codecs\.decode|marshal\.loads|
            binascii\.unhexlify)\s*\( |
        \b(exec|eval)\s*\(\s*(compile\s*\(\s*)?__import__\s*\(\s*['"](base64|zlib|marshal|codecs)['"] |
        \b(exec|eval)\s*\(\s*compile\s*\(\s*(base64|zlib|marshal|codecs)\. |
        \b(exec|eval)\s*\(\s*['"]{0,3}\s*\.join\s*\(\s*(map\s*\(\s*chr|\[?\s*chr\s*\() |
        \bexec\s*\(\s*\w+\s*\(\s*(base64\.b64decode|zlib\.decompress)
    )""",
    re.VERBOSE,
)
_HEX_IDENTIFIERS = re.compile(r"\b_0x[0-9a-f]{4,}\b")
_CHARCODE_CHAIN = re.compile(r"String\.fromCharCode\s*\((\s*(0x[0-9a-f]+|\d+)\s*,){15,}", re.I)
_CHARCODE_CALL = re.compile(r"String\.fromCharCode\s*\(")
_CHR_CHAIN = re.compile(r"(chr\s*\(\s*\d+\s*\)\s*\+\s*){8,}")
# A long run with no whitespace or quotes: the body of an encoded string literal.
_DENSE_RUN = re.compile(r"[A-Za-z0-9+/=_\-\\]{200,}")
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]{500,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){200,}|(?:\\x[0-9a-fA-F]{2}){100,}")
_BENIGN_CONTEXT = re.compile(
    r"data:[\w/+.-]+;base64,|sourceMappingURL=|sha(256|384|512)-|-----BEGIN (CERTIFICATE|PUBLIC KEY)"
)
_SKIP_PATH = re.compile(
    r"(^|/)(node_modules|vendor|vendors|third_party|__snapshots__|fixtures?|testdata)/"
    r"|\.(map|svg|lock)$|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$"
)
_BUNDLE_PATH = re.compile(r"\.min\.(js|cjs|mjs)$|(^|/)(dist|build|bundle|umd|esm|cjs|lib)/")
TINY_FILES = 5
TINY_BYTES = 50 * 1024


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in Counter(text).values())


def _is_tiny(ctx: PackageContext) -> bool:
    return len(ctx.code) <= TINY_FILES and ctx.total_code_bytes <= TINY_BYTES


def _line_at(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    return text[start : end if end != -1 else len(text)]


def _benign_blob(text: str, start: int) -> bool:
    return bool(_BENIGN_CONTEXT.search(text[max(0, start - 120) : start + 40]))


def _scan_file(path: str, text: str, tiny: bool) -> dict[str, Evidence]:
    """Return at most one piece of evidence per obfuscation sub-type."""
    hits: dict[str, Evidence] = {}
    if "eval" in text or "exec" in text or "Function" in text:
        match = _OBFUSCATED_EXEC.search(text)
        if match:
            hits["exec"] = Evidence(path, _line_at(text, match.start()))
    if "exec" not in hits and "_0x" in text:
        if len(set(_HEX_IDENTIFIERS.findall(text))) >= 20:
            hits["exec"] = Evidence(path, _line_at(text, text.find("_0x")))
    if "fromCharCode" in text or "chr(" in text or "chr (" in text:
        match = _CHARCODE_CHAIN.search(text) or _CHR_CHAIN.search(text)
        if match or len(_CHARCODE_CALL.findall(text)) >= 12:
            index = match.start() if match else text.find("String.fromCharCode")
            hits["charcode"] = Evidence(path, _line_at(text, index))
    bundled = bool(_BUNDLE_PATH.search(path)) and not tiny
    if not bundled:
        for match in _DENSE_RUN.finditer(text):
            body = match.group(0)
            if _benign_blob(text, match.start()):
                continue
            if shannon_entropy(body[:4096]) > 5.0:
                hits["entropy"] = Evidence(path, body)
                break
            if shannon_entropy(body[:4096]) < 3.0:
                continue  # padding or a repeated character, not an encoded payload
            if "blob" not in hits and (_BASE64.fullmatch(body) or _HEX.search(body)):
                hits["blob"] = Evidence(path, body)
        if "entropy" in hits:
            hits.pop("blob", None)
    if tiny and len(text) >= 2048:
        lines = text.splitlines() or [text]
        longest = max(len(line) for line in lines)
        if longest > 5000 or len(text) / len(lines) > 500:
            hits["minified"] = Evidence(path, max(lines, key=len))
    return hits


_SUBTYPES = {
    # sub-type: (weight key, severity, message)
    "exec": (
        "obfuscated_exec",
        "high",
        "Code decodes or unpacks a hidden payload and executes it.",
    ),
    "charcode": (
        "fromcharcode_chain",
        "medium",
        "Strings are assembled from long character-code chains.",
    ),
    "entropy": (
        "high_entropy_string",
        "low",
        "Long high-entropy string literal (entropy above 5.0 bits per character).",
    ),
    "blob": ("encoded_blob", "low", "Long base64 or hex blob embedded in source code."),
    "minified": (
        "minified_tiny_package",
        "low",
        "Minified or single-line code inside an otherwise tiny package.",
    ),
}


def detect_obfuscation(ctx: PackageContext) -> list[Finding]:
    tiny = _is_tiny(ctx)
    found: dict[str, Evidence] = {}
    counts: Counter[str] = Counter()
    for path, text in ctx.scan_code.items():
        if _SKIP_PATH.search(path):
            continue
        for subtype, evidence in _scan_file(path, text, tiny).items():
            found.setdefault(subtype, evidence)
            counts[subtype] += 1
    out = []
    for subtype, (key, severity, message) in _SUBTYPES.items():
        if subtype not in found:
            continue
        extra = f" (in {counts[subtype]} files)" if counts[subtype] > 1 else ""
        out.append(
            Finding(
                "obfuscation", severity, ctx.config.weight(key), message + extra, found[subtype]
            )
        )
    return out


DETECTORS = (detect_obfuscation,)
