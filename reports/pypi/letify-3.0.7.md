# Suspicious package report: `letify` 3.0.7 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `letify` |
| Version | `3.0.7` |
| Ecosystem | pypi |
| Risk score | 87 / 100 (high) |
| Published | 2026-11-22T18:29:47Z |
| Scanned | 2026-11-23T22:15:55Z |
| Registry page | https://pypi.org/project/letify/3.0.7/ |
| Possibly imitating | `libify` |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `letify/transport/nat.py`:

  ```text
  path = Path.home() / ".ssh" / "authorized_keys"
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `letify/providers/elice.py`:

  ```text
  "curl -fsSL https://raw.githubusercontent.com/elice-dev/eci-cli/main/scripts/install.sh | sh"
  ```

- **typosquat** (low, +12): Name is 2 edit(s) from popular package 'libify' (two edits apart).

## Suggested text for an upstream report

The pypi package `letify` version `3.0.7` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Name is 2 edit(s) from popular package 'libify' (two edits apart).

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fletify%403.0.7&package=pypi%2Fletify%403.0.7
