# Suspicious package report: `pymeep` 1.36.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `pymeep` |
| Version | `1.36.0` |
| Ecosystem | pypi |
| Risk score | 72 / 100 (high) |
| Published | 2026-11-19T21:54:37Z |
| Scanned | 2026-11-21T04:10:13Z |
| Registry page | https://pypi.org/project/pymeep/1.36.0/ |
| Possibly imitating | `pymeeus` |

## Indicators

- **python-install-code** (medium, +25): setup.py subprocess.run() starts a process at install time.

  Evidence in `pymeep-1.36.0/setup.py:127`:

  ```text
  out = subprocess.run(
  ```

- **new-publisher-similar-name** (medium, +20): Recently created package from a publisher with little history, with a name similar to popular package 'pymeeus'.
- **python-install-code** (low, +15): setup.py class egg_info overrides the 'setuptools.command.egg_info.egg_info' command at install time.

  Evidence in `pymeep-1.36.0/setup.py:348`:

  ```text
  class egg_info(_egg_info):
  ```

- **typosquat** (low, +12): Name is 2 edit(s) from popular package 'pymeeus' (two edits apart).

## Suggested text for an upstream report

The pypi package `pymeep` version `1.36.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- setup.py subprocess.run() starts a process at install time.
- Recently created package from a publisher with little history, with a name similar to popular package 'pymeeus'.
- setup.py class egg_info overrides the 'setuptools.command.egg_info.egg_info' command at install time.
- Name is 2 edit(s) from popular package 'pymeeus' (two edits apart).

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fpymeep%401.36.0&package=pypi%2Fpymeep%401.36.0
