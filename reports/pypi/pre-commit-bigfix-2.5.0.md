# Suspicious package report: `pre-commit-bigfix` 2.5.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `pre-commit-bigfix` |
| Version | `2.5.0` |
| Ecosystem | pypi |
| Risk score | 80 / 100 (high) |
| Published | 2026-11-20T17:20:53Z |
| Scanned | 2026-11-22T07:16:07Z |
| Registry page | https://pypi.org/project/pre-commit-bigfix/2.5.0/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it. (in 3 files)

  Evidence in `pre_commit_bigfix/bes_content_score_risk.py`:

  ```text
  to ASCII, or eval( unescape( atob( Function( fromCharCode(
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `pre_commit_bigfix/bes_content_score_risk.py`:

  ```text
  Invoke-WebRequest, DownloadString, bitsadmin, ...)
  ```


## Suggested text for an upstream report

The pypi package `pre-commit-bigfix` version `2.5.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it. (in 3 files)
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fpre-commit-bigfix%402.5.0&package=pypi%2Fpre-commit-bigfix%402.5.0
