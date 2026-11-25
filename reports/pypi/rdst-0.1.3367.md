# Suspicious package report: `rdst` 0.1.3367 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `rdst` |
| Version | `0.1.3367` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-24T16:53:29Z |
| Scanned | 2026-11-25T20:42:00Z |
| Registry page | https://pypi.org/project/rdst/0.1.3367/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `rdst-0.1.3367/shared/ssh_tunnel.py`:

  ```text
  config_path = Path.home() / ".ssh" / "config"
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `rdst-0.1.3367/install.sh`:

  ```text
  info "Uninstall with: curl -fsSL https://downloads.readyset.io/packages/rdst-cli/install.sh | sh -s -- --uninstall"
  ```


## Suggested text for an upstream report

The pypi package `rdst` version `0.1.3367` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Frdst%400.1.3367&package=pypi%2Frdst%400.1.3367
