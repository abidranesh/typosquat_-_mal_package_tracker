# Suspicious package report: `mystack-rig` 1.2.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `mystack-rig` |
| Version | `1.2.0` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-15T20:15:44Z |
| Scanned | 2026-11-16T02:25:52Z |
| Registry page | https://pypi.org/project/mystack-rig/1.2.0/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `cli/remote_dev.py`:

  ```text
  config_path = os.path.expanduser(ssh_config_path or "~/.ssh/config")
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `cli/remote_dev.py`:

  ```text
  curl -fsSL https://opencode.ai/install.sh | sh
  ```


## Suggested text for an upstream report

The pypi package `mystack-rig` version `1.2.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fmystack-rig%401.2.0&package=pypi%2Fmystack-rig%401.2.0
