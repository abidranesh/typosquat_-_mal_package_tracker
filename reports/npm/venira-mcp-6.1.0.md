# Suspicious package report: `venira-mcp` 6.1.0 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `venira-mcp` |
| Version | `6.1.0` |
| Ecosystem | npm |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-23T17:29:36Z |
| Scanned | 2026-11-25T02:26:28Z |
| Registry page | https://www.npmjs.com/package/venira-mcp/v/6.1.0 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/dist/scripts/measure-shell-asks.js`:

  ```text
  "rm -rf /tmp/other-project", "cp secrets.txt /etc/hosts", "echo x > ~/.bashrc", "cat ~/.ssh/id_rsa",
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/dist/scripts/measure-shell-asks.js`:

  ```text
  "npm view lodash version", "curl -s https://api.github.com/repos/nodejs/node", "curl -I https://example.com",
  ```


## Suggested text for an upstream report

The npm package `venira-mcp` version `6.1.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Fvenira-mcp%406.1.0&package=npm%2Fvenira-mcp%406.1.0
