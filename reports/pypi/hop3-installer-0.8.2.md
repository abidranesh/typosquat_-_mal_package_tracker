# Suspicious package report: `hop3-installer` 0.8.2 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `hop3-installer` |
| Version | `0.8.2` |
| Ecosystem | pypi |
| Risk score | 79 / 100 (high) |
| Published | 2026-11-15T18:59:50Z |
| Scanned | 2026-11-16T02:25:52Z |
| Registry page | https://pypi.org/project/hop3-installer/0.8.2/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `hop3_installer/server_installer/nix.py`:

  ```text
  ``/etc/passwd``), which root would follow on the next redeploy.
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `hop3_installer/server_installer/deps_common.py`:

  ```text
  'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs '
  ```

- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The pypi package `hop3-installer` version `0.8.2` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fhop3-installer%400.8.2&package=pypi%2Fhop3-installer%400.8.2
