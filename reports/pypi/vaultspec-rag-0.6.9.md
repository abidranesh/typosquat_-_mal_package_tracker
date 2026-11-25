# Suspicious package report: `vaultspec-rag` 0.6.9 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `vaultspec-rag` |
| Version | `0.6.9` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-24T08:41:29Z |
| Scanned | 2026-11-25T11:39:06Z |
| Registry page | https://pypi.org/project/vaultspec-rag/0.6.9/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `vaultspec_rag-0.6.9/tools/monitor/smoke.py`:

  ```text
  Path("C:/Program Files/Google/Chrome/Application/chrome.exe"),
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `vaultspec_rag-0.6.9/src/vaultspec_rag/service_runtime.py`:

  ```text
  return "curl -LsSf https://astral.sh/uv/install.sh | sh"
  ```


## Suggested text for an upstream report

The pypi package `vaultspec-rag` version `0.6.9` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fvaultspec-rag%400.6.9&package=pypi%2Fvaultspec-rag%400.6.9
