# Suspicious package report: `axor-wrap` 0.3.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `axor-wrap` |
| Version | `0.3.0` |
| Ecosystem | pypi |
| Risk score | 70 / 100 (high) |
| Published | 2026-11-21T12:53:30Z |
| Scanned | 2026-11-23T01:54:32Z |
| Registry page | https://pypi.org/project/axor-wrap/0.3.0/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `axor_wrap/agents/skills.py`:

  ```text
  # a sentence around a command (`cat ~/.aws/credentials` in prose)
  ```

- **exfiltration** (medium, +30): Code serialises the whole process environment in a file that makes network calls.

  Evidence in `axor_wrap/agents/rules.py`:

  ```text
  r"^\s*(?:printenv|env|set|export\s+-p)\s*(?:$|\||>)"
  ```


## Suggested text for an upstream report

The pypi package `axor-wrap` version `0.3.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code serialises the whole process environment in a file that makes network calls.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Faxor-wrap%400.3.0&package=pypi%2Faxor-wrap%400.3.0
