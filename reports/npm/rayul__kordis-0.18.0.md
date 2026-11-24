# Suspicious package report: `@rayul/kordis` 0.18.0 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@rayul/kordis` |
| Version | `0.18.0` |
| Ecosystem | npm |
| Risk score | 74 / 100 (high) |
| Published | 2026-11-22T15:26:36Z |
| Scanned | 2026-11-24T06:16:30Z |
| Registry page | https://www.npmjs.com/package/@rayul/kordis/v/0.18.0 |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `package/dist/index.js`:

  ```text
  hint: "Encoded eval (`eval(atob(...))`) is a hallmark of obfuscated payloads. Move the logic into plain code the reader can audit."
  ```

- **npm-install-hook** (medium, +25): 'postinstall' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "node scripts/postinstall.mjs"
  ```

- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The npm package `@rayul/kordis` version `0.18.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- 'postinstall' script runs a bundled JavaScript file at install time.
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40rayul%2Fkordis%400.18.0&package=npm%2F%40rayul%2Fkordis%400.18.0
