# Suspicious package report: `swm-gpu` 0.3.17 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `swm-gpu` |
| Version | `0.3.17` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-15T11:59:15Z |
| Scanned | 2026-11-15T14:43:12Z |
| Registry page | https://pypi.org/project/swm-gpu/0.3.17/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `swm/providers/vultr.py`:

  ```text
  path = pathlib.Path.home() / ".ssh" / name
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `swm/bootstrap_frameworks.py`:

  ```text
  answering = (f"(curl -s -o /dev/null --max-time 3 http://127.0.0.1:{port}/ "
  ```


## Suggested text for an upstream report

The pypi package `swm-gpu` version `0.3.17` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fswm-gpu%400.3.17&package=pypi%2Fswm-gpu%400.3.17
