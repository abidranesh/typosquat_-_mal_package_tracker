# Suspicious package report: `@dreamlake/dreamlake-cli` 0.125.4 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@dreamlake/dreamlake-cli` |
| Version | `0.125.4` |
| Ecosystem | npm |
| Risk score | 84 / 100 (high) |
| Published | 2026-11-15T13:56:39Z |
| Scanned | 2026-11-16T02:25:52Z |
| Registry page | https://www.npmjs.com/package/@dreamlake/dreamlake-cli/v/0.125.4 |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `package/dist/cli/hosts/remote.js`:

  ```text
  const remote = `python3 -c 'import base64;exec(base64.b64decode("${source}"))'`;
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/bin/dreamlake.js`:

  ```text
  " curl -fsSL https://dl.dreamlake.ai/install.sh | sh\n",
  ```

- **sparse-metadata** (info, +4): Missing or placeholder README.

## Suggested text for an upstream report

The npm package `@dreamlake/dreamlake-cli` version `0.125.4` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Code downloads a file and then executes it or marks it executable.
- Missing or placeholder README.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40dreamlake%2Fdreamlake-cli%400.125.4&package=npm%2F%40dreamlake%2Fdreamlake-cli%400.125.4
