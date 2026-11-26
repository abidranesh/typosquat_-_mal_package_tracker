# Suspicious package report: `pkgxray` 1.3.0 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `pkgxray` |
| Version | `1.3.0` |
| Ecosystem | npm |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-24T18:28:37Z |
| Scanned | 2026-11-26T03:13:00Z |
| Registry page | https://www.npmjs.com/package/pkgxray/v/1.3.0 |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `package/src/auditor.js`:

  ```text
  // (`eval(atob(x))`, `new Function(decode(blob))`), which is what we keep.
  ```

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/src/quarantine.js`:

  ```text
  // `~/.aws/credentials`). The same filter blocks block-device / FIFO / etc.
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/src/auditor.js`:

  ```text
  const GYP_NETWORK_TOKEN_RE = /(?:https?:\/\/|(?:^|[\s;&|`$(])(?:curl|wget)\s|Invoke-WebRequest)/im;
  ```

- **suspicious-endpoint** (medium, +20): URL with a raw IP address instead of a hostname.

  Evidence in `package/src/auditor.js`:

  ```text
  // execute: `// e.g. request.get('https://1.2.3.4/')` (superagent), an Apache
  ```


## Suggested text for an upstream report

The npm package `pkgxray` version `1.3.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- URL with a raw IP address instead of a hostname.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Fpkgxray%401.3.0&package=npm%2Fpkgxray%401.3.0
