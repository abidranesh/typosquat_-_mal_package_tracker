# Suspicious package report: `@zonease/happy` 0.6.70 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@zonease/happy` |
| Version | `0.6.70` |
| Ecosystem | npm |
| Risk score | 90 / 100 (high) |
| Published | 2026-11-22T05:11:57Z |
| Scanned | 2026-11-23T22:15:55Z |
| Registry page | https://www.npmjs.com/package/@zonease/happy/v/0.6.70 |

## Indicators

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/scripts/claude_version_utils.cjs`:

  ```text
  * - macOS/Linux: curl -fsSL https://claude.ai/install.sh | bash
  ```

- **exfiltration** (medium, +30): Code serialises the whole process environment in a file that makes network calls.

  Evidence in `package/dist/api-CqRClg8e.mjs`:

  ```text
  return `printf '%s' '${MARKER}'; '${escapedNode}' -e 'process.stdout.write(JSON.stringify(process.env))'`;
  ```

- **npm-install-hook** (medium, +25): 'postinstall' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "node scripts/unpack-tools.cjs"
  ```


## Suggested text for an upstream report

The npm package `@zonease/happy` version `0.6.70` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code downloads a file and then executes it or marks it executable.
- Code serialises the whole process environment in a file that makes network calls.
- 'postinstall' script runs a bundled JavaScript file at install time.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40zonease%2Fhappy%400.6.70&package=npm%2F%40zonease%2Fhappy%400.6.70
