# Suspicious package report: `browser-harness` 0.1.14 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `browser-harness` |
| Version | `0.1.14` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-24T08:17:50Z |
| Scanned | 2026-11-25T11:39:06Z |
| Registry page | https://pypi.org/project/browser-harness/0.1.14/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `browser_harness/daemon.py`:

  ```text
  state = json.loads((base / "Local State").read_text(encoding="utf-8", errors="replace"))
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `browser_harness/admin.py`:

  ```text
  raise RuntimeError("profile-use not installed -- curl -fsSL https://browser-use.com/profile.sh | sh")
  ```


## Suggested text for an upstream report

The pypi package `browser-harness` version `0.1.14` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fbrowser-harness%400.1.14&package=pypi%2Fbrowser-harness%400.1.14
