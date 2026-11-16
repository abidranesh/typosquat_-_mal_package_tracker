# Suspicious package report: `rafter-cli` 0.12.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `rafter-cli` |
| Version | `0.12.0` |
| Ecosystem | pypi |
| Risk score | 79 / 100 (high) |
| Published | 2026-11-16T00:41:18Z |
| Scanned | 2026-11-16T20:28:36Z |
| Registry page | https://pypi.org/project/rafter-cli/0.12.0/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `rafter_cli/utils/binary_manager.py`:

  ```text
  entry that's a symlink to e.g. `~/.ssh/authorized_keys`; the subsequent
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `rafter_cli/core/risk_rules.py`:

  ```text
  # `eval "$(cat f)"` / `eval "$(curl -s http://x)"` -- a program-executing
  ```

- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The pypi package `rafter-cli` version `0.12.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Frafter-cli%400.12.0&package=pypi%2Frafter-cli%400.12.0
