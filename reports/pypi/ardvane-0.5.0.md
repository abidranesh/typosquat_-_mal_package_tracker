# Suspicious package report: `ardvane` 0.5.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `ardvane` |
| Version | `0.5.0` |
| Ecosystem | pypi |
| Risk score | 85 / 100 (high) |
| Published | 2026-11-19T06:25:48Z |
| Scanned | 2026-11-20T08:29:01Z |
| Registry page | https://pypi.org/project/ardvane/0.5.0/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `ardvane/scanner/tests/run_tests.py`:

  ```text
  "catch/pth-runs-hidden-code": {"lib/evil.pth": "import base64;exec(base64.b64decode('cHJpbnQoMSk='))\n"},
  ```

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `ardvane/scanner/safeinstall.py`:

  ```text
  for name in ("package.json", "package-lock.json", "npm-shrinkwrap.json", ".npmrc"):
  ```


## Suggested text for an upstream report

The pypi package `ardvane` version `0.5.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fardvane%400.5.0&package=pypi%2Fardvane%400.5.0
