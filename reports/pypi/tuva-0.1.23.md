# Suspicious package report: `tuva` 0.1.23 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `tuva` |
| Version | `0.1.23` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-16T22:09:49Z |
| Scanned | 2026-11-18T03:03:37Z |
| Registry page | https://pypi.org/project/tuva/0.1.23/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `tuva/_backend/services/rao/writing_assistant.py`:

  ```text
  absolute paths like /etc/passwd would be slurped into the LLM prompt).
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `tuva_sdk/error_catalog.py`:

  ```text
  "steps": {"macos": ["Check you’re online, then choose Try again.", "Or install it yourself: in Terminal, run `curl -fsSL https://chatgpt.com/codex/install.sh | sh`, then come back to this page."], "l…
  ```


## Suggested text for an upstream report

The pypi package `tuva` version `0.1.23` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Ftuva%400.1.23&package=pypi%2Ftuva%400.1.23
