# Suspicious package report: `install-anything-skill` 3.1.0 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `install-anything-skill` |
| Version | `3.1.0` |
| Ecosystem | npm |
| Risk score | 85 / 100 (high) |
| Published | 2026-11-16T22:41:36Z |
| Scanned | 2026-11-18T03:03:37Z |
| Registry page | https://www.npmjs.com/package/install-anything-skill/v/3.1.0 |

## Indicators

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/scripts/install.sh`:

  ```text
  # curl -fsSL https://raw.githubusercontent.com/Ayan-Jain-737/install-anything-skill/main/scripts/install.sh | bash
  ```

- **npm-install-hook** (medium, +25): 'install' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "install": "node scripts/postinstall.js"
  ```

- **npm-install-hook** (medium, +25): 'postinstall' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "node scripts/postinstall.js"
  ```


## Suggested text for an upstream report

The npm package `install-anything-skill` version `3.1.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code downloads a file and then executes it or marks it executable.
- 'install' script runs a bundled JavaScript file at install time.
- 'postinstall' script runs a bundled JavaScript file at install time.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Finstall-anything-skill%403.1.0&package=npm%2Finstall-anything-skill%403.1.0
