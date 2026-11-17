# Suspicious package report: `@clawops/cli` 2.5.1 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@clawops/cli` |
| Version | `2.5.1` |
| Ecosystem | npm |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-16T16:41:22Z |
| Scanned | 2026-11-17T21:12:59Z |
| Registry page | https://www.npmjs.com/package/@clawops/cli/v/2.5.1 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/dist/harden-LOF24XSO.js`:

  ```text
  `cat /home/clawops/.ssh/authorized_keys 2>/dev/null || true`
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/dist/chunk-CIRE5NLK.js`:

  ```text
  const r2 = await exec("curl -fsSL https://tailscale.com/install.sh | sh");
  ```


## Suggested text for an upstream report

The npm package `@clawops/cli` version `2.5.1` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40clawops%2Fcli%402.5.1&package=npm%2F%40clawops%2Fcli%402.5.1
