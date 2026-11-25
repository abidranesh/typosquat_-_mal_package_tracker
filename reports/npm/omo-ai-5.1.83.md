# Suspicious package report: `omo-ai` 5.1.83 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `omo-ai` |
| Version | `5.1.83` |
| Ecosystem | npm |
| Risk score | 81 / 100 (high) |
| Published | 2026-11-24T02:47:46Z |
| Scanned | 2026-11-25T11:39:06Z |
| Registry page | https://www.npmjs.com/package/omo-ai/v/5.1.83 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/plugin/extensions/omo-feedback.js`:

  ```text
  import{randomUUID as e}from"node:crypto";import{AsyncLocalStorage as t}from"node:async_hooks";import{createHash as n}from"node:crypto";import{mkdir as r}from"node:fs/promises";import{join as i}from"n…
  ```

- **npm-install-hook** (medium, +25): 'postinstall' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "node bin/senpi-patch.mjs"
  ```

- **obfuscation** (low, +12): Long high-entropy string literal (entropy above 5.0 bits per character).

  Evidence in `package/plugin/extensions/omo-telemetry-otlp.js`:

  ```text
  CipvcGVudGVsZW1ldHJ5L3Byb3RvL2NvbW1vbi92MS9jb21tb24ucHJvdG8SHW9wZW50ZWxlbWV0cnkucHJvdG8uY29tbW9uLnYxIowCCghBbnlWYWx1ZRIWCgxzdHJpbmdfdmFsdWUYASABKAlIABIUCgpib29sX3ZhbHVlGAIgASgISAASEwoJaW50X3ZhbHVlGAM…
  ```

- **sparse-metadata** (info, +4): Missing or placeholder README.

## Suggested text for an upstream report

The npm package `omo-ai` version `5.1.83` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- 'postinstall' script runs a bundled JavaScript file at install time.
- Long high-entropy string literal (entropy above 5.0 bits per character).
- Missing or placeholder README.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Fomo-ai%405.1.83&package=npm%2Fomo-ai%405.1.83
