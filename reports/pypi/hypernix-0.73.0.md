# Suspicious package report: `hypernix` 0.73.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `hypernix` |
| Version | `0.73.0` |
| Ecosystem | pypi |
| Risk score | 95 / 100 (high) |
| Published | 2026-11-20T17:14:18Z |
| Scanned | 2026-11-22T07:16:07Z |
| Registry page | https://pypi.org/project/hypernix/0.73.0/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `hypernix/system/netops.py`:

  ```text
  known_hosts = known_hosts or Path.home() / ".ssh" / "known_hosts"
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `hypernix/monitoring/tvtop_max.py`:

  ```text
  " Install it: curl -fsSL https://bun.sh/install | bash\n"
  ```

- **suspicious-endpoint** (medium, +20): URL with a raw IP address instead of a hostname.

  Evidence in `hypernix/t1api/claudecode.py`:

  ```text
  hnx claude --server http://100.64.0.7:8000 --key T1-...
  ```


## Suggested text for an upstream report

The pypi package `hypernix` version `0.73.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- URL with a raw IP address instead of a hostname.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fhypernix%400.73.0&package=pypi%2Fhypernix%400.73.0
