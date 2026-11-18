# Suspicious package report: `@gopher.security/gopher-mcp-js` 0.1.44-1 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@gopher.security/gopher-mcp-js` |
| Version | `0.1.44-1` |
| Ecosystem | npm |
| Risk score | 85 / 100 (high) |
| Published | 2026-11-16T13:30:24Z |
| Scanned | 2026-11-18T03:03:37Z |
| Registry page | https://www.npmjs.com/package/@gopher.security/gopher-mcp-js/v/0.1.44-1 |

## Indicators

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/scripts/check-node-version.js`:

  ```text
  ' curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -',
  ```

- **npm-install-hook** (medium, +25): 'preinstall' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "preinstall": "node scripts/check-node-version.js"
  ```

- **npm-install-hook** (medium, +25): 'postinstall' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "node scripts/download-native.js || true"
  ```


## Suggested text for an upstream report

The npm package `@gopher.security/gopher-mcp-js` version `0.1.44-1` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code downloads a file and then executes it or marks it executable.
- 'preinstall' script runs a bundled JavaScript file at install time.
- 'postinstall' script runs a bundled JavaScript file at install time.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40gopher.security%2Fgopher-mcp-js%400.1.44-1&package=npm%2F%40gopher.security%2Fgopher-mcp-js%400.1.44-1
