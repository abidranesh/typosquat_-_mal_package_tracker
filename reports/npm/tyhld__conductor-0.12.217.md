# Suspicious package report: `@tyhld/conductor` 0.12.217 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@tyhld/conductor` |
| Version | `0.12.217` |
| Ecosystem | npm |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-24T04:23:22Z |
| Scanned | 2026-11-25T11:39:06Z |
| Registry page | https://www.npmjs.com/package/@tyhld/conductor/v/0.12.217 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/dist/proto-profile.js`:

  ```text
  * ★既定の型の deny（.env/.ssh/鍵/本番DB書込などの「床」）はそのまま引き継ぎ、その上に足す。
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/scripts/autoupdate-install.sh`:

  ```text
  claude_lines+=("curl -fsSL https://claude.ai/install.sh | bash -s stable")
  ```


## Suggested text for an upstream report

The npm package `@tyhld/conductor` version `0.12.217` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40tyhld%2Fconductor%400.12.217&package=npm%2F%40tyhld%2Fconductor%400.12.217
