# Suspicious package report: `nio-cat` 0.9.25 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `nio-cat` |
| Version | `0.9.25` |
| Ecosystem | npm |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-26T11:53:54Z |
| Scanned | 2026-11-27T22:51:54Z |
| Registry page | https://www.npmjs.com/package/nio-cat/v/0.9.25 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/src/ssh.js`:

  ```text
  // Servidors que ja tens a ~/.ssh/config (sense comodins), perquè el panell els ofereixi i no calgui escriure'ls.
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/web/app/app.js`:

  ```text
  const SH_CMD = 'curl -fsSL https://www.nio.cat/install.sh | sh', WIN_CMD = 'irm https://www.nio.cat/install.ps1 | iex';
  ```


## Suggested text for an upstream report

The npm package `nio-cat` version `0.9.25` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Fnio-cat%400.9.25&package=npm%2Fnio-cat%400.9.25
