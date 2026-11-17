# Suspicious package report: `bhooai-nexus` 5.5.22 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `bhooai-nexus` |
| Version | `5.5.22` |
| Ecosystem | npm |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-16T06:20:16Z |
| Scanned | 2026-11-17T12:17:23Z |
| Registry page | https://www.npmjs.com/package/bhooai-nexus/v/5.5.22 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/src/cli/commands/login.js`:

  ```text
  /** Idempotently write/replace the registry auth line in ~/.npmrc. */
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/src/cli/devEdge.js`:

  ```text
  const res = await fetch(NGINX_ZIP, { signal: AbortSignal.timeout(120000) });
  ```


## Suggested text for an upstream report

The npm package `bhooai-nexus` version `5.5.22` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Fbhooai-nexus%405.5.22&package=npm%2Fbhooai-nexus%405.5.22
