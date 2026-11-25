# Suspicious package report: `@rtzh/gy-cesium` 0.0.82 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@rtzh/gy-cesium` |
| Version | `0.0.82` |
| Ecosystem | npm |
| Risk score | 74 / 100 (high) |
| Published | 2026-11-24T03:59:51Z |
| Scanned | 2026-11-25T11:39:06Z |
| Registry page | https://www.npmjs.com/package/@rtzh/gy-cesium/v/0.0.82 |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it. (in 3 files)

  Evidence in `package/lib/v2.7/gy-cesium.es.js`:

  ```text
  import * as _0x275e3b from "@rtzh/cesium";
  ```

- **npm-install-hook** (medium, +25): 'postinstall' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "node ./scripts/postinstall.js"
  ```

- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The npm package `@rtzh/gy-cesium` version `0.0.82` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it. (in 3 files)
- 'postinstall' script runs a bundled JavaScript file at install time.
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40rtzh%2Fgy-cesium%400.0.82&package=npm%2F%40rtzh%2Fgy-cesium%400.0.82
