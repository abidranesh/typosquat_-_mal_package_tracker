# Suspicious package report: `@programinglive/dev-workflow-mcp-server` 1.32.8 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@programinglive/dev-workflow-mcp-server` |
| Version | `1.32.8` |
| Ecosystem | npm |
| Risk score | 80 / 100 (high) |
| Published | 2026-11-18T19:18:39Z |
| Scanned | 2026-11-20T00:56:48Z |
| Registry page | https://www.npmjs.com/package/@programinglive/dev-workflow-mcp-server/v/1.32.8 |

## Indicators

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/scripts/bootstrap-unix.sh`:

  ```text
  brew install rtk || curl -fsSL https://raw.githubusercontent.com/rtk-ai/rtk/refs/heads/master/install.sh | sh
  ```

- **npm-install-hook** (medium, +25): 'postinstall' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "node install.js"
  ```

- **suspicious-endpoint** (medium, +20): URL with a raw IP address instead of a hostname.

  Evidence in `package/scripts/session-reaper.cjs`:

  ```text
  const DEFAULT_MONITOR = process.env.DEVWF_MONITOR_URL || 'http://100.77.138.14:3100';
  ```


## Suggested text for an upstream report

The npm package `@programinglive/dev-workflow-mcp-server` version `1.32.8` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code downloads a file and then executes it or marks it executable.
- 'postinstall' script runs a bundled JavaScript file at install time.
- URL with a raw IP address instead of a hostname.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40programinglive%2Fdev-workflow-mcp-server%401.32.8&package=npm%2F%40programinglive%2Fdev-workflow-mcp-server%401.32.8
