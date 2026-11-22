# Suspicious package report: `bendit` 0.3.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `bendit` |
| Version | `0.3.0` |
| Ecosystem | pypi |
| Risk score | 80 / 100 (high) |
| Published | 2026-11-20T17:44:20Z |
| Scanned | 2026-11-22T07:16:07Z |
| Registry page | https://pypi.org/project/bendit/0.3.0/ |
| Possibly imitating | `bandit` |

## Indicators

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `bendit/install.sh`:

  ```text
  command -v curl >/dev/null 2>&1 && say 'curl -fsSL https://claude.ai/install.sh | bash'
  ```

- **typosquat** (medium, +25): Name is 1 edit(s) from popular package 'bandit' (one character substituted).
- **new-publisher-similar-name** (medium, +20): Recently created package from a publisher with little history, with a name similar to popular package 'bandit'.

## Suggested text for an upstream report

The pypi package `bendit` version `0.3.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code downloads a file and then executes it or marks it executable.
- Name is 1 edit(s) from popular package 'bandit' (one character substituted).
- Recently created package from a publisher with little history, with a name similar to popular package 'bandit'.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fbendit%400.3.0&package=pypi%2Fbendit%400.3.0
