# Suspicious package report: `lium.io` 0.46.3 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `lium.io` |
| Version | `0.46.3` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-17T20:35:04Z |
| Scanned | 2026-11-19T01:31:48Z |
| Registry page | https://pypi.org/project/lium.io/0.46.3/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `lium_io-0.46.3/e2e/conftest.py`:

  ```text
  """Delete from the account the SSH keys whose public key is one of `home`/.ssh/*.pub — every run mints a fresh key
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `lium_io-0.46.3/mine.sh`:

  ```text
  # curl -fsSL https://raw.githubusercontent.com/Datura-ai/lium-cli/main/mine.sh | bash -s -- -k <HOTKEY>
  ```


## Suggested text for an upstream report

The pypi package `lium.io` version `0.46.3` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Flium.io%400.46.3&package=pypi%2Flium.io%400.46.3
