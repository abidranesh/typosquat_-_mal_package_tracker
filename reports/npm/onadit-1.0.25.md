# Suspicious package report: `onadit` 1.0.25 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `onadit` |
| Version | `1.0.25` |
| Ecosystem | npm |
| Risk score | 91 / 100 (high) |
| Published | 2026-11-26T12:21:29Z |
| Scanned | 2026-11-27T22:51:54Z |
| Registry page | https://www.npmjs.com/package/onadit/v/1.0.25 |

## Indicators

- **npm-install-hook** (high, +40): 'postinstall' script runs a shell, downloader or inline code at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "node -e "const e=process.env;if(e.RIFT_SKIP_POSTINSTALL_MENUBAR==='1'||(e.RIFT_POSTINSTALL_MENUBAR!=='1'&&e.npm_config_global!=='true'&&e.npm_config_location!=='global'))process.exit(…
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/dist/src/diagnostics/install-layout.d.ts`:

  ```text
  export declare const REINSTALL_COMMAND = "curl -fsSL https://onadit.com/install | bash";
  ```

- **obfuscation** (low, +12): Long high-entropy string literal (entropy above 5.0 bits per character).

  Evidence in `package/operator/swiftbar/render-menu.py`:

  ```text
  iVBORw0KGgoAAAANSUhEUgAAAJAAAACQCAYAAADnRuK4AAAB6klEQVR42u3dYa3CMBSA0UpAQiVNAhKQUAeTNElIgC78J6F3dFt3TnIV9Mtrst48UgIAAAAAAAAAAK4u15nrLGazedS5XSGeUudl/jLPOnfxmOhMo15bDrffX6LhrrPZwXad4a6yxaF2nSIgIyABCUh…
  ```

- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The npm package `onadit` version `1.0.25` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- 'postinstall' script runs a shell, downloader or inline code at install time.
- Code downloads a file and then executes it or marks it executable.
- Long high-entropy string literal (entropy above 5.0 bits per character).
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Fonadit%401.0.25&package=npm%2Fonadit%401.0.25
