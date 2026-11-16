# Suspicious package report: `pyqcd` 0.4.3 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `pyqcd` |
| Version | `0.4.3` |
| Ecosystem | pypi |
| Risk score | 80 / 100 (high) |
| Published | 2026-11-16T00:47:39Z |
| Scanned | 2026-11-16T20:28:36Z |
| Registry page | https://pypi.org/project/pyqcd/0.4.3/ |
| Possibly imitating | `pyocd` |

## Indicators

- **python-install-code** (medium, +25): setup.py subprocess.run() starts a process at install time.

  Evidence in `pyqcd-0.4.3/setup.py:137`:

  ```text
  subprocess.run([compiler, str(source), "-o", str(Path(tmp) / "probe")],
  ```

- **new-publisher-similar-name** (medium, +20): Recently created package from a publisher with little history, with a name similar to popular package 'pyocd'.
- **python-install-code** (low, +15): setup.py writes a file outside the build directory at install time.

  Evidence in `pyqcd-0.4.3/setup.py:57`:

  ```text
  with open("/dev/tty", "w") as terminal:
  ```

- **typosquat** (low, +12): Name is 1 edit(s) from popular package 'pyocd' (one character substituted).
- **obfuscation** (low, +8): Long base64 or hex blob embedded in source code.

  Evidence in `pyqcd-0.4.3/pyqcd/einsum/_topology_registry.py`:

  ```text
  f10abadeeef7d85e4a69800b634ff0f4ac292143f70df0b04a7c1af641c4c3ae59acd92ed442c4a12f0d0f49fb0c4df1161a4c3546a2ff01705596e13c1ca59144dfb28ed762468f60cbcbed336a0e99f5b5375e874d755b416ca788d4b00165fdabc12…
  ```


## Suggested text for an upstream report

The pypi package `pyqcd` version `0.4.3` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- setup.py subprocess.run() starts a process at install time.
- Recently created package from a publisher with little history, with a name similar to popular package 'pyocd'.
- setup.py writes a file outside the build directory at install time.
- Name is 1 edit(s) from popular package 'pyocd' (one character substituted).
- Long base64 or hex blob embedded in source code.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fpyqcd%400.4.3&package=pypi%2Fpyqcd%400.4.3
