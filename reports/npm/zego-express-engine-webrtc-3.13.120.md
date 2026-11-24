# Suspicious package report: `zego-express-engine-webrtc` 3.13.120 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `zego-express-engine-webrtc` |
| Version | `3.13.120` |
| Ecosystem | npm |
| Risk score | 90 / 100 (high) |
| Published | 2026-11-23T11:24:07Z |
| Scanned | 2026-11-24T18:06:13Z |
| Registry page | https://www.npmjs.com/package/zego-express-engine-webrtc/v/3.13.120 |

## Indicators

- **npm-install-hook** (medium, +25): 'preinstall' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "preinstall": "node ./scripts/pre-check.js"
  ```

- **npm-install-hook** (medium, +25): 'postinstall' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "node ./scripts/check.js"
  ```

- **obfuscation** (medium, +20): Strings are assembled from long character-code chains.

  Evidence in `package/background-process/index.js`:

  ```text
  !function(t,i){if("object"==typeof exports&&"object"==typeof module)module.exports=i();else if("function"==typeof define&&define.amd)define([],i);else{var n=i();for(var r in n)("object"==typeof expor…
  ```

- **obfuscation** (low, +12): Long high-entropy string literal (entropy above 5.0 bits per character).

  Evidence in `package/background-process/index.js`:

  ```text
  LyohCiogT05OWCBSdW50aW1lIFdlYiB2MS4xNS4wCiogQ29weXJpZ2h0IChjKSBNaWNyb3NvZnQgQ29ycG9yYXRpb24uIEFsbCByaWdodHMgcmVzZXJ2ZWQuCiogTGljZW5zZWQgdW5kZXIgdGhlIE1JVCBMaWNlbnNlLgoqLwohZnVuY3Rpb24oZSx0KXsib2JqZWN…
  ```

- **sparse-metadata** (info, +8): Missing or placeholder README, repository URL.

## Suggested text for an upstream report

The npm package `zego-express-engine-webrtc` version `3.13.120` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- 'preinstall' script runs a bundled JavaScript file at install time.
- 'postinstall' script runs a bundled JavaScript file at install time.
- Strings are assembled from long character-code chains.
- Long high-entropy string literal (entropy above 5.0 bits per character).
- Missing or placeholder README, repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Fzego-express-engine-webrtc%403.13.120&package=npm%2Fzego-express-engine-webrtc%403.13.120
