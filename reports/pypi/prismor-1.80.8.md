# Suspicious package report: `prismor` 1.80.8 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `prismor` |
| Version | `1.80.8` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-26T23:44:32Z |
| Scanned | 2026-11-28T04:42:45Z |
| Registry page | https://pypi.org/project/prismor/1.80.8/ |
| Possibly imitating | `prison` |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `prismor/runtime/learning.py`:

  ```text
  """Host aliases and HostNames the user declared in ~/.ssh/config."""
  ```

- **python-install-code** (medium, +30): A .pth file contains an executable import line that runs on every Python start-up.

  Evidence in `immunity-agent.pth`:

  ```text
  import sys; exec("try:\n import prismor.runtime._post_install; prismor.runtime._post_install.maybe_show()\nexcept Exception:\n pass")
  ```

- **exfiltration** (medium, +30): Code serialises the whole process environment in a file that makes network calls.

  Evidence in `prismor/runtime/setup_wizard.py`:

  ```text
  ("secret-exfiltration", "CRITICAL", "secret_exfiltration", "Blocks cat .env | curl, piping secrets to external hosts"),
  ```

- **typosquat** (low, +6): Name is 2 edit(s) from popular package 'prison' (two edits apart).

## Suggested text for an upstream report

The pypi package `prismor` version `1.80.8` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- A .pth file contains an executable import line that runs on every Python start-up.
- Code serialises the whole process environment in a file that makes network calls.
- Name is 2 edit(s) from popular package 'prison' (two edits apart).

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fprismor%401.80.8&package=pypi%2Fprismor%401.80.8
