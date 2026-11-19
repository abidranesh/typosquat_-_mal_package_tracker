# Suspicious package report: `triss-coworker` 0.44.5 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `triss-coworker` |
| Version | `0.44.5` |
| Ecosystem | npm |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-18T15:19:26Z |
| Scanned | 2026-11-19T18:42:17Z |
| Registry page | https://www.npmjs.com/package/triss-coworker/v/0.44.5 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/src/opencode2-preflight.js`:

  ```text
  'cat ~/.ssh/id_rsa',
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/src/setup/engines.js`:

  ```text
  // omp's installHint() is `curl https://omp.sh/install | sh # minimum …` —
  ```


## Suggested text for an upstream report

The npm package `triss-coworker` version `0.44.5` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Ftriss-coworker%400.44.5&package=npm%2Ftriss-coworker%400.44.5
