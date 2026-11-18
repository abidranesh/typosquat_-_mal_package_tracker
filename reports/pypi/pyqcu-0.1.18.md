# Suspicious package report: `pyqcu` 0.1.18 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `pyqcu` |
| Version | `0.1.18` |
| Ecosystem | pypi |
| Risk score | 72 / 100 (high) |
| Published | 2026-11-17T16:23:45Z |
| Scanned | 2026-11-18T19:38:35Z |
| Registry page | https://pypi.org/project/pyqcu/0.1.18/ |
| Possibly imitating | `pyicu` |

## Indicators

- **python-install-code** (medium, +25): setup.py subprocess.run() starts a process at install time.

  Evidence in `pyqcu-0.1.18/setup.py:107`:

  ```text
  subprocess.run(
  ```

- **new-publisher-similar-name** (medium, +20): Recently created package from a publisher with little history, with a name similar to popular package 'pyicu'.
- **python-install-code** (low, +15): setup.py writes a file outside the build directory at install time.

  Evidence in `pyqcu-0.1.18/setup.py:57`:

  ```text
  with open("/dev/tty", "w") as terminal:
  ```

- **typosquat** (low, +12): Name is 1 edit(s) from popular package 'pyicu' (one character substituted).

## Suggested text for an upstream report

The pypi package `pyqcu` version `0.1.18` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- setup.py subprocess.run() starts a process at install time.
- Recently created package from a publisher with little history, with a name similar to popular package 'pyicu'.
- setup.py writes a file outside the build directory at install time.
- Name is 1 edit(s) from popular package 'pyicu' (one character substituted).

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fpyqcu%400.1.18&package=pypi%2Fpyqcu%400.1.18
