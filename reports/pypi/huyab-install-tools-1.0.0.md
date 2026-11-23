# Suspicious package report: `huyab-install-tools` 1.0.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `huyab-install-tools` |
| Version | `1.0.0` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-21T14:52:21Z |
| Scanned | 2026-11-23T01:54:32Z |
| Registry page | https://pypi.org/project/huyab-install-tools/1.0.0/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `install_tools/install-tools.sh`:

  ```text
  local config="$HOME/.ssh/config"
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `install_tools/install-tools.sh`:

  ```text
  curl -fsSL https://raw.githubusercontent.com/nguyenhuy158/huyabhome/main/scripts/install-tools.sh | bash
  ```


## Suggested text for an upstream report

The pypi package `huyab-install-tools` version `1.0.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fhuyab-install-tools%401.0.0&package=pypi%2Fhuyab-install-tools%401.0.0
