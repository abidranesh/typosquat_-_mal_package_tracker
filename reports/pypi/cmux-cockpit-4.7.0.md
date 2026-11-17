# Suspicious package report: `cmux-cockpit` 4.7.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `cmux-cockpit` |
| Version | `4.7.0` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-16T17:58:47Z |
| Scanned | 2026-11-17T21:12:59Z |
| Registry page | https://pypi.org/project/cmux-cockpit/4.7.0/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `cockpit/lib/preflight.py`:

  ```text
  f"{yellow('cockpit:')} leftover machine-local state in {COCKPIT_HOME} "
  ```

- **unsafe-archive** (high, +40): Archive contains absolute or parent-directory paths and was not unpacked.

  Evidence in `(archive)`:

  ```text
  unsafe: link escapes archive: 'cmux_cockpit-4.7.0/.github/copilot-instructions.md' -> '../AGENTS.md'
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `cockpit/cockpit.py`:

  ```text
  _CSHIP_INSTALL = "curl -fsSL https://cship.dev/install.sh | bash"
  ```

- **sparse-metadata** (info, +8): Missing or placeholder README, repository URL.

## Suggested text for an upstream report

The pypi package `cmux-cockpit` version `4.7.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Archive contains absolute or parent-directory paths and was not unpacked.
- Code downloads a file and then executes it or marks it executable.
- Missing or placeholder README, repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fcmux-cockpit%404.7.0&package=pypi%2Fcmux-cockpit%404.7.0
