# Suspicious package report: `py-edge-telemetry` 0.1.1 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `py-edge-telemetry` |
| Version | `0.1.1` |
| Ecosystem | pypi |
| Risk score | 83 / 100 (high) |
| Published | 2026-11-15T14:50:37Z |
| Scanned | 2026-11-15T17:55:06Z |
| Registry page | https://pypi.org/project/py-edge-telemetry/0.1.1/ |

## Indicators

- **python-install-code** (medium, +25): setup.py subprocess.run() starts a process at install time.

  Evidence in `py_edge_telemetry-0.1.1/setup.py:66`:

  ```text
  subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
  ```

- **binary-dropper** (medium, +20): Compiled executable or library in a package that is not declared as native.

  Evidence in `py_edge_telemetry-0.1.1/kfedge/xmrig`:

  ```text
  py_edge_telemetry-0.1.1/kfedge/xmrig (ELF)
  ```

- **python-install-code** (low, +15): setup.py class PostInstall overrides the 'setuptools.command.install.install' command at install time.

  Evidence in `py_edge_telemetry-0.1.1/setup.py:7`:

  ```text
  class PostInstall(install):
  ```

- **python-install-code** (low, +15): setup.py writes a file outside the build directory at install time.

  Evidence in `py_edge_telemetry-0.1.1/setup.py:64`:

  ```text
  with open("/etc/systemd/system/kfedgetel.service", "w") as f:
  ```

- **sparse-metadata** (info, +8): Missing or placeholder README, repository URL.

## Suggested text for an upstream report

The pypi package `py-edge-telemetry` version `0.1.1` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- setup.py subprocess.run() starts a process at install time.
- Compiled executable or library in a package that is not declared as native.
- setup.py class PostInstall overrides the 'setuptools.command.install.install' command at install time.
- setup.py writes a file outside the build directory at install time.
- Missing or placeholder README, repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fpy-edge-telemetry%400.1.1&package=pypi%2Fpy-edge-telemetry%400.1.1
