"""Exfiltration detectors: credential access combined with network use, and
hardcoded collection endpoints (webhooks, tunnels, paste sites, raw IP addresses)."""

from __future__ import annotations

import ipaddress
import re

from ..context import Evidence, Finding, PackageContext

MAX_SCAN = 256 * 1024

# Cheap substring pre-filters: the regular expressions only run on files that contain
# one of these, which keeps large packages fast.
_SENSITIVE_HINTS = (
    ".ssh", ".aws", ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".docker", ".kube",
    "/etc/passwd", "/etc/shadow", "login data", "local state", "user data", "chrome",
    ".mozilla", "logins.json", "cookies.sqlite", "key3.db", "key4.db", "leveldb", "discord",
    "wallet", "electrum", "exodus", "solana", "nkbihfbeogaeaoehlefnkodbefgpgknn", "keystore",
    "{24}",
)  # fmt: skip
_ENV_HINTS = ("process.env", "os.environ", "printenv", "env |", "env|")
_ENDPOINT_HINTS = (
    "webhooks", "telegram", "ngrok", "pipedream", ".oast.", "interact.sh", "oastify",
    "burpcollaborator", "dnslog", "ceye.io", "webhook.site", "requestbin", "requestcatcher",
    "pastebin", "paste.ee", "hastebin", "rentry", "transfer.sh", "0x0.st", "ghostbin",
    "anonfiles", "file.io",
)  # fmt: skip


def _hinted(lowered: str, hints: tuple[str, ...]) -> bool:
    return any(hint in lowered for hint in hints)


_SENSITIVE = re.compile(
    r"""(
        \.ssh[/\\]+(id_\w+|authorized_keys|config) | ['"/\\]\.ssh['"/\\] |
        \.aws[/\\]+credentials | \.npmrc\b | \.pypirc\b | \.netrc\b | \.git-credentials\b |
        \.docker[/\\]+config\.json | \.kube[/\\]+config | /etc/(passwd|shadow)\b |
        Login\ Data | Local\ State | User\ Data[/\\]+Default | Google[/\\]+Chrome |
        \.mozilla[/\\]+firefox | (?<![\w-])logins\.json | cookies\.sqlite | key[34]\.db |
        Local\ Storage[\s"',/\\+]+leveldb | discord(canary|ptb)?[/\\]+ |
        \{24\}\\+\.\[\\+w-\]\{6\} |
        wallet\.dat | Electrum[/\\]+wallets | Exodus[/\\]+exodus\.wallet | \.config[/\\]+solana |
        nkbihfbeogaeaoehlefnkodbefgpgknn | \bkeystore[/\\]+UTC-- | Ethereum[/\\]+keystore
    )""",
    re.VERBOSE | re.IGNORECASE,
)
# The whole environment being serialised or handed to a request. Copying the environment
# for a subprocess (``os.environ.copy()``) is routine and deliberately not matched.
_ENV_DUMP = re.compile(
    r"""(
        JSON\.stringify\s*\(\s*process\.env\s*[,)] |
        (body|data|json|payload)\s*:\s*process\.env\s*[,}] |
        Object\.(entries|keys)\s*\(\s*process\.env\s*\)[^;\n]{0,160}(fetch|request|post|send|write)\s*\( |
        (str|json\.dumps|repr|urlencode)\s*\(\s*(dict\s*\(\s*)?os\.environ\s*\) |
        (data|json|params|payload|body)\s*=\s*(dict\s*\(\s*)?os\.environ\b(?!\s*[\[.]) |
        \bprintenv\s*\| | \benv\s*\|\s*(curl|nc|base64|wget)
    )""",
    re.VERBOSE,
)
# A file-read primitive: a sensitive path only counts when something nearby reads it.
_READ = re.compile(
    r"""(
        \bopen\s*\( | \.read_(text|bytes)\s*\( | \breadFile(Sync)?\s*\( | \bcreateReadStream\s*\( |
        \breaddir(Sync)?\s*\( | \bos\.(listdir|walk|scandir)\s*\( | \bglob(\.glob|Sync)?\s*\( |
        \bsqlite3\.connect\s*\( | \bshutil\.copy\w*\s*\( | \bcopyFile(Sync)?\s*\( |
        \bGet-Content\b | \bcat\s+[~/$"'] | \bFile\.ReadAll\w+
    )""",
    re.VERBOSE,
)
READ_WINDOW = 400
_NETWORK = re.compile(
    r"""(
        require\s*\(\s*['"](node:)?(https?|net|dgram|dns|tls|axios|node-fetch|request|got|
            superagent|ws|needle|undici)['"]\s*\) |
        from\s+['"](node:)?(https?|net|dgram|dns|axios|node-fetch|got|undici)['"] |
        \bfetch\s*\( | \bXMLHttpRequest\b | \bWebSocket\s*\( | \bsendBeacon\s*\( |
        \burllib\.request\b | \burllib2\b | \burlopen\s*\( | \brequests\.(get|post|put|request|Session)\b |
        \bhttpx\.\w+ | \baiohttp\b | \bsocket\.socket\s*\( | \bhttp\.client\b | \bsmtplib\b |
        \b(curl|wget)\s+ | \bInvoke-(WebRequest|RestMethod)\b | \bnslookup\s
    )""",
    re.VERBOSE,
)

_ENDPOINTS = [
    (
        "Discord webhook",
        re.compile(r"discord(?:app)?\.com(?:\.[a-z0-9.-]+)?/api/webhooks/[\w-]+", re.I),
    ),
    (
        "Telegram bot API",
        re.compile(r"api\.telegram\.org(?:\.[a-z0-9.-]+)?/bot[\w:-]+", re.I),
    ),
    ("ngrok tunnel", re.compile(r"[a-z0-9-]{3,63}\.ngrok(?:-free)?\.(?:io|app|dev)\b", re.I)),
    ("Pipedream endpoint", re.compile(r"[a-z0-9-]{3,63}\.(?:m|x)\.pipedream\.net\b", re.I)),
    (
        "out-of-band interaction host",
        re.compile(
            r"[a-z0-9-]{3,63}\.oast\.(?:fun|live|site|online|pro|me)\b|[a-z0-9-]{3,63}\.interact\.sh\b"
            r"|[a-z0-9-]{3,63}\.oastify\.com\b|[a-z0-9-]{3,63}\.burpcollaborator\.net\b|[a-z0-9-]{3,63}\.dnslog\.cn\b"
            r"|[a-z0-9-]{3,63}\.ceye\.io\b",
            re.I,
        ),
    ),
    (
        "request-capture service",
        re.compile(
            r"webhook\.site/[\w-]+|[a-z0-9-]{3,63}\.requestbin\.\w+|requestcatcher\.com", re.I
        ),
    ),
    (
        "paste or file-drop host",
        re.compile(
            r"pastebin\.com/raw|paste\.ee/[rd]/|hastebin\.com/raw|rentry\.co/\w+/raw"
            r"|transfer\.sh/|0x0\.st/|ghostbin\.\w+/|anonfiles\.com/|file\.io/\w",
            re.I,
        ),
    ),
]
_IP_URL = re.compile(r"\b(?:https?|ftp|wss?)://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:[/'\"\s]|$)")


def _line_at(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    return text[start : end if end != -1 else len(text)]


def _is_test_path(path: str) -> bool:
    return bool(re.search(r"(^|/)(tests?|__tests__|spec|examples?|docs?)/|\.(test|spec)\.", path))


def _read_sensitive(text: str) -> re.Match[str] | None:
    """The first sensitive path that has a file-read call close to it."""
    for match in _SENSITIVE.finditer(text):
        window = text[max(0, match.start() - READ_WINDOW) : match.end() + READ_WINDOW]
        if _READ.search(window):
            return match
    return None


def detect_exfiltration(ctx: PackageContext) -> list[Finding]:
    """Sensitive files or the whole environment read in a file that also talks to the network."""
    out: dict[str, Finding] = {}
    for path, text in ctx.scan_code.items():
        if _is_test_path(path):
            continue
        lowered = text.lower()
        sensitive = _read_sensitive(text) if _hinted(lowered, _SENSITIVE_HINTS) else None
        dump = _ENV_DUMP.search(text) if _hinted(lowered, _ENV_HINTS) else None
        if not (sensitive or dump) or not _NETWORK.search(text):
            continue
        if sensitive and "credentials" not in out:
            out["credentials"] = Finding(
                "exfiltration",
                "high",
                ctx.config.weight("credential_access_network"),
                "Code reads credential, browser, chat-token or wallet files and also makes "
                "network calls in the same file.",
                Evidence(path, _line_at(text, sensitive.start())),
            )
        if dump and "env" not in out:
            out["env"] = Finding(
                "exfiltration",
                "medium",
                ctx.config.weight("env_exfiltration"),
                "Code serialises the whole process environment in a file that makes network calls.",
                Evidence(path, _line_at(text, dump.start())),
            )
    return list(out.values())


def _public_ip(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not (
        address.is_private
        and not _documentation(address)
        or address.is_loopback
        or address.is_unspecified
        or address.is_link_local
        or address.is_multicast
    )


def _documentation(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """TEST-NET ranges count as public here: Python marks them private, attackers' samples
    and our synthetic fixtures use them, and no legitimate package ships them in code."""
    return any(
        address in ipaddress.ip_network(net)
        for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    )


def detect_suspicious_endpoints(ctx: PackageContext) -> list[Finding]:
    """Hardcoded collection endpoints and raw-IP URLs in shipped code."""
    out: dict[str, Finding] = {}
    sources = dict(ctx.scan_code)
    for path, text in ctx.texts.items():
        if path.endswith("package.json") and path.count("/") <= 1:
            sources[path] = text[:MAX_SCAN]
    for path in sorted(sources):
        if _is_test_path(path):
            continue
        text = sources[path]
        if "endpoint" not in out and _hinted(text.lower(), _ENDPOINT_HINTS):
            for label, pattern in _ENDPOINTS:
                match = pattern.search(text)
                if match:
                    out["endpoint"] = Finding(
                        "suspicious-endpoint",
                        "medium",
                        ctx.config.weight("suspicious_endpoint"),
                        f"Hardcoded {label} in package code.",
                        Evidence(path, _line_at(text, match.start())),
                    )
                    break
        if "ip" not in out and "://" in text:
            for match in _IP_URL.finditer(text):
                if _public_ip(match.group(1)):
                    out["ip"] = Finding(
                        "suspicious-endpoint",
                        "medium",
                        ctx.config.weight("raw_ip_url"),
                        "URL with a raw IP address instead of a hostname.",
                        Evidence(path, _line_at(text, match.start())),
                    )
                    break
    return list(out.values())


DETECTORS = (detect_exfiltration, detect_suspicious_endpoints)
