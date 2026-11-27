# Suspicious package report: `@pareto4/pp-core` 1.26.0 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@pareto4/pp-core` |
| Version | `1.26.0` |
| Ecosystem | npm |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-25T16:52:43Z |
| Scanned | 2026-11-27T04:25:57Z |
| Registry page | https://www.npmjs.com/package/@pareto4/pp-core/v/1.26.0 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/scripts/live-runs/driver.cjs`:

  ```text
  'Read(~/.ssh/**)', 'Read(~/.aws/**)', 'Read(~/.config/gh/**)', 'Read(~/.npmrc)',
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/bin/install.js`:

  ```text
  curl -fsSL https://fnm.vercel.app/install | bash
  ```


## Suggested text for an upstream report

The npm package `@pareto4/pp-core` version `1.26.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40pareto4%2Fpp-core%401.26.0&package=npm%2F%40pareto4%2Fpp-core%401.26.0
