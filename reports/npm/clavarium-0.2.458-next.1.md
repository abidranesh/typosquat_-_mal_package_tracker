# Suspicious package report: `clavarium` 0.2.458-next.1 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `clavarium` |
| Version | `0.2.458-next.1` |
| Ecosystem | npm |
| Risk score | 79 / 100 (high) |
| Published | 2026-11-15T11:23:26Z |
| Scanned | 2026-11-15T14:43:12Z |
| Registry page | https://www.npmjs.com/package/clavarium/v/0.2.458-next.1 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/deploy/online.mjs`:

  ```text
  const script = `f="$HOME/.ssh/authorized_keys"; [ -f "$f" ] || exit 0; t="$(mktemp)"; grep -vF -- ${quote(body)} "$f" > "$t" || true; cat "$t" > "$f"; rm -f -- "$t"`;
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/deploy/clavarium.mjs`:

  ```text
  + ' curl -fsSL https://clavarium.org/install.sh | sudo bash install, on Ubuntu 24.04 or 26.04 (local mode)\n'
  ```

- **sparse-metadata** (info, +4): Missing or placeholder README.

## Suggested text for an upstream report

The npm package `clavarium` version `0.2.458-next.1` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Missing or placeholder README.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Fclavarium%400.2.458-next.1&package=npm%2Fclavarium%400.2.458-next.1
