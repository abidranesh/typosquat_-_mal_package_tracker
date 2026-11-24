# Suspicious package report: `calkit-python` 0.52.3 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `calkit-python` |
| Version | `0.52.3` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-23T00:49:13Z |
| Scanned | 2026-11-24T06:16:30Z |
| Registry page | https://pypi.org/project/calkit-python/0.52.3/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `calkit/workspace.py`:

  ```text
  """Whether ``~/.ssh/config`` already has a Host block for this host."""
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `calkit/install.py`:

  ```text
  "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs "
  ```


## Suggested text for an upstream report

The pypi package `calkit-python` version `0.52.3` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fcalkit-python%400.52.3&package=pypi%2Fcalkit-python%400.52.3
