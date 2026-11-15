# Suspicious package report: `shadok-ai` 0.19.56 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `shadok-ai` |
| Version | `0.19.56` |
| Ecosystem | npm |
| Risk score | 74 / 100 (high) |
| Published | 2026-11-15T12:18:29Z |
| Scanned | 2026-11-15T17:55:06Z |
| Registry page | https://www.npmjs.com/package/shadok-ai/v/0.19.56 |

## Indicators

- **npm-install-hook** (high, +40): 'postinstall' script runs a shell, downloader or inline code at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "chmod +x node_modules/node-pty/prebuilds/*/spawn-helper 2>/dev/null || true"
  ```

- **exfiltration** (medium, +30): Code serialises the whole process environment in a file that makes network calls.

  Evidence in `package/dist/group-exec.d.ts`:

  ```text
  * guard on a SIBLING would read the sibling's secrets (`env | curl …`) — in
  ```

- **sparse-metadata** (info, +4): Missing or placeholder README.

## Suggested text for an upstream report

The npm package `shadok-ai` version `0.19.56` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- 'postinstall' script runs a shell, downloader or inline code at install time.
- Code serialises the whole process environment in a file that makes network calls.
- Missing or placeholder README.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Fshadok-ai%400.19.56&package=npm%2Fshadok-ai%400.19.56
