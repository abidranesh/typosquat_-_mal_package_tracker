# Suspicious package report: `@flisk-sh/flisk` 1.4.75 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@flisk-sh/flisk` |
| Version | `1.4.75` |
| Ecosystem | npm |
| Risk score | 87 / 100 (high) |
| Published | 2026-11-24T18:55:18Z |
| Scanned | 2026-11-26T03:13:00Z |
| Registry page | https://www.npmjs.com/package/@flisk-sh/flisk/v/1.4.75 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/cli/dist-bundle/chunk-AHSXRXHB.js`:

  ```text
  for (const candidate of [join(projectRoot, ".npmrc"), join(projectRoot, PACKAGE_JSON)]) {
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/cli/dist-bundle/chunk-QYPJL4QJ.js`:

  ```text
  " curl -fsSL https://flisk.sh/install.sh | sh",
  ```

- **obfuscation** (low, +12): Long high-entropy string literal (entropy above 5.0 bits per character).

  Evidence in `package/cli/dist-bundle/chunk-4LXVKKLN.js`:

  ```text
  iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAMAAADDpiTIAAAABlBMVEUWo0r///+zeCNEAAAFKklEQVR42u3c0XEYORDEUE7+SSsCfam4IomHCDgNeFW+s70WAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA…
  ```


## Suggested text for an upstream report

The npm package `@flisk-sh/flisk` version `1.4.75` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Long high-entropy string literal (entropy above 5.0 bits per character).

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40flisk-sh%2Fflisk%401.4.75&package=npm%2F%40flisk-sh%2Fflisk%401.4.75
