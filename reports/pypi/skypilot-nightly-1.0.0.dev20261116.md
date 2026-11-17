# Suspicious package report: `skypilot-nightly` 1.0.0.dev20261116 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `skypilot-nightly` |
| Version | `1.0.0.dev20261116` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-16T03:43:53Z |
| Scanned | 2026-11-17T03:14:19Z |
| Registry page | https://pypi.org/project/skypilot-nightly/1.0.0.dev20261116/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `sky/utils/git.py`:

  ```text
  logger.debug('SSH config file ~/.ssh/config does not exist')
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `sky/cloud_stores.py`:

  ```text
  'curl https://rclone.org/install.sh | sudo bash',
  ```


## Suggested text for an upstream report

The pypi package `skypilot-nightly` version `1.0.0.dev20261116` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fskypilot-nightly%401.0.0.dev20261116&package=pypi%2Fskypilot-nightly%401.0.0.dev20261116
