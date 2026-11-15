"""Python install-time code detector.

``setup.py`` is parsed with ``ast`` (never imported or executed) and searched for
network access, process spawning, dynamic code execution, payload decoding and
writes outside the build directory. Executable ``.pth`` files are flagged too.
"""

from __future__ import annotations

import ast
import re

from ..context import Evidence, Finding, PackageContext

_NETWORK_PREFIXES = (
    "urllib.request.", "urllib2.", "urllib.urlopen", "urllib.urlretrieve", "requests.",
    "httpx.", "socket.", "http.client.", "httplib.", "ftplib.", "aiohttp.", "urllib3.",
    "smtplib.", "paramiko.", "telnetlib.",
)  # fmt: skip
_PROCESS_NAMES = {
    "os.system", "os.popen", "os.startfile", "pty.spawn", "commands.getoutput",
    "commands.getstatusoutput",
}  # fmt: skip
_PROCESS_PREFIXES = ("subprocess.", "os.exec", "os.spawn", "os.posix_spawn")
_DECODE_NAMES = {
    "base64.b64decode", "base64.b32decode", "base64.b16decode", "base64.a85decode",
    "base64.b85decode", "base64.decodebytes", "base64.urlsafe_b64decode", "bytes.fromhex",
    "bytearray.fromhex", "codecs.decode", "zlib.decompress", "lzma.decompress",
    "bz2.decompress", "gzip.decompress", "marshal.loads", "binascii.unhexlify",
    "binascii.a2b_base64",
}  # fmt: skip
_EXEC_NAMES = {"exec", "eval", "builtins.exec", "builtins.eval", "__builtins__.exec"}
_HOME_CALLS = {
    "os.path.expanduser", "pathlib.Path.home", "Path.home", "tempfile.gettempdir",
    "tempfile.mkdtemp", "tempfile.mkstemp", "os.getenv", "os.environ.get",
    "site.getsitepackages", "site.getusersitepackages", "sysconfig.get_path",
}  # fmt: skip
# Build tooling that a setup.py may reasonably shell out to.
_BENIGN_COMMANDS = {
    "git", "hg", "svn", "cmake", "make", "ninja", "pkg-config", "gcc", "g++", "cc", "clang",
    "swig", "cython", "protoc", "rustc", "cargo", "llvm-config", "pg_config", "mysql_config",
    "uname", "python-config", "python3-config", "gfortran", "ld", "nm", "ar",
}  # fmt: skip
_INSTALL_BASES = {"install", "develop", "egg_info"}
_ABSOLUTE = re.compile(r"^(/|~|[A-Za-z]:[\\/]|%[A-Z]+%)")
_PTH_BENIGN = re.compile(
    r"^import\s+(_virtualenv|__editable__\w*|_distutils_hack|_distutils_system_mod)\b"
    r"|^import os; var = 'SETUPTOOLS_USE_DISTUTILS'"
    r"|^import sys, ?types, ?os;.*(__path__|importlib)"
)


def _dotted(node: ast.AST, aliases: dict[str, str]) -> str | None:
    """Resolve ``a.b.c`` call targets to dotted names, following import aliases."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Call):  # e.g. __import__("os").system
        inner = _dotted(node.func, aliases)
        if inner == "__import__" and node.args and isinstance(node.args[0], ast.Constant):
            parts.append(str(node.args[0].value))
            return ".".join(reversed(parts))
        return None
    if not isinstance(node, ast.Name):
        return None
    parts.append(aliases.get(node.id, node.id))
    return ".".join(reversed(parts))


def _first_command(node: ast.AST) -> str | None:
    """The program name of a literal command, if it can be read statically."""
    if isinstance(node, ast.List | ast.Tuple) and node.elts:
        node = node.elts[0]
    if isinstance(node, ast.JoinedStr) and node.values:
        node = node.values[0]
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.strip():
        return node.value.split()[0].rsplit("/", 1)[-1]
    return None


class _SetupVisitor(ast.NodeVisitor):
    def __init__(self, source: str):
        self.lines = source.splitlines()
        self.aliases: dict[str, str] = {}
        self.hits: dict[str, tuple[int, str]] = {}  # category -> (line number, detail)

    def _hit(self, category: str, node: ast.AST, detail: str) -> None:
        self.hits.setdefault(category, (getattr(node, "lineno", 1), detail))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = (
                alias.name if alias.asname else alias.name.split(".")[0]
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = f"{node.module or ''}.{alias.name}"

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for base in node.bases:
            name = _dotted(base, self.aliases) or ""
            if name.rsplit(".", 1)[-1] in _INSTALL_BASES:
                self._hit("cmdclass", node, f"class {node.name} overrides the '{name}' command")
        self.generic_visit(node)

    def _calls_in(self, node: ast.AST) -> set[str]:
        return {
            name
            for sub in ast.walk(node)
            if isinstance(sub, ast.Call) and (name := _dotted(sub.func, self.aliases))
        }

    def _is_decoded(self, node: ast.AST) -> bool:
        calls = self._calls_in(node)
        if calls & _DECODE_NAMES or "__import__" in calls:
            return True
        if any(c.startswith(_NETWORK_PREFIXES) or c.endswith(".urlopen") for c in calls):
            return True
        return any(
            isinstance(sub, ast.Constant)
            and isinstance(sub.value, str | bytes)
            and len(sub.value) >= 200
            for sub in ast.walk(node)
        )

    @staticmethod
    def _reads_local_file(node: ast.AST) -> bool:
        """``exec(open("pkg/version.py").read())`` and friends: a common, benign idiom."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "compile" and node.args:
                return _SetupVisitor._reads_local_file(node.args[0])
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            return False
        if node.func.attr not in ("read", "read_text"):
            return False
        owner = node.func.value
        if isinstance(owner, ast.Name):
            return True
        return (
            isinstance(owner, ast.Call)
            and isinstance(owner.func, ast.Name)
            and owner.func.id in ("open", "Path")
        )

    def _outside_path(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                if _ABSOLUTE.match(sub.value):
                    return True
            elif isinstance(sub, ast.Call):
                if (_dotted(sub.func, self.aliases) or "") in _HOME_CALLS:
                    return True
            elif isinstance(sub, ast.Attribute) and _dotted(sub, self.aliases) == "os.environ":
                return True
        return False

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func, self.aliases) or ""
        if name in _EXEC_NAMES and node.args:
            arg = node.args[0]
            if self._is_decoded(arg):
                self._hit("exec_decoded", node, f"{name}() runs decoded or downloaded content")
            elif not self._reads_local_file(arg):
                self._hit("exec", node, f"{name}() runs dynamically built code")
        elif name in _PROCESS_NAMES or name.startswith(_PROCESS_PREFIXES):
            command = _first_command(node.args[0]) if node.args else None
            if command not in _BENIGN_COMMANDS:
                self._hit("process", node, f"{name}() starts a process")
        elif name.startswith(_NETWORK_PREFIXES) or name.rsplit(".", 1)[-1] in (
            "urlopen",
            "urlretrieve",
        ):
            self._hit("network", node, f"{name}() opens a network connection")
        elif name in _DECODE_NAMES:
            self._hit("decode", node, f"{name}() decodes an embedded payload")
        elif name in ("open", "io.open") and len(node.args) >= 2:
            mode = node.args[1]
            writes = (
                isinstance(mode, ast.Constant)
                and isinstance(mode.value, str)
                and any(flag in mode.value for flag in "wax+")
            )
            if writes and self._outside_path(node.args[0]):
                self._hit("write", node, "writes a file outside the build directory")
        elif name.startswith("shutil.") and len(node.args) >= 2:
            if self._outside_path(node.args[1]):
                self._hit("write", node, f"{name}() copies a file outside the build directory")
        self.generic_visit(node)


_CATEGORIES = {
    # category: (weight key, severity)
    "exec_decoded": ("setup_exec_decoded", "high"),
    "exec": ("setup_exec", "medium"),
    "network": ("setup_network", "medium"),
    "process": ("setup_process", "medium"),
    "decode": ("setup_base64", "low"),
    "write": ("setup_file_write", "low"),
    "cmdclass": ("setup_cmdclass_install", "low"),
}


_SDIST_SETUP = re.compile(r"^[^/]+-\d[^/]*/setup\.py$")


def _setup_files(ctx: PackageContext) -> list[str]:
    """``setup.py`` at an sdist root. A ``pkg/setup.py`` module inside a wheel never runs
    at install time, so it is left to the general content detectors."""
    out = []
    for path in ctx.texts:
        if path == "setup.py" or _SDIST_SETUP.match(path):
            out.append(path)
        elif path.endswith("/setup.py") and path.count("/") == 1:
            if f"{path.split('/', 1)[0]}/PKG-INFO" in ctx.file_sizes:
                out.append(path)
    return sorted(out)


def detect_setup_code(ctx: PackageContext) -> list[Finding]:
    out = []
    for path in _setup_files(ctx):
        source = ctx.texts[path]
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            continue
        visitor = _SetupVisitor(source)
        try:
            visitor.visit(tree)
        except RecursionError:
            continue
        for category, (line, detail) in visitor.hits.items():
            key, severity = _CATEGORIES[category]
            snippet = visitor.lines[line - 1] if 0 < line <= len(visitor.lines) else ""
            out.append(
                Finding(
                    "python-install-code",
                    severity,
                    ctx.config.weight(key),
                    f"setup.py {detail} at install time.",
                    Evidence(f"{path}:{line}", snippet),
                )
            )
    return out


def detect_pth_files(ctx: PackageContext) -> list[Finding]:
    """``.pth`` lines starting with ``import`` run on every interpreter start-up."""
    for path in sorted(p for p in ctx.texts if p.lower().endswith(".pth")):
        if path.endswith("-nspkg.pth"):
            continue
        for line in ctx.texts[path].splitlines():
            stripped = line.strip()
            if stripped.startswith(("import ", "import\t")) and not _PTH_BENIGN.match(stripped):
                return [
                    Finding(
                        "python-install-code",
                        "medium",
                        ctx.config.weight("pth_executable"),
                        "A .pth file contains an executable import line that runs on every "
                        "Python start-up.",
                        Evidence(path, stripped),
                    )
                ]
    return []


DETECTORS = (detect_setup_code, detect_pth_files)
