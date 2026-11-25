# Suspicious package report: `buckthorn` 0.2.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `buckthorn` |
| Version | `0.2.0` |
| Ecosystem | pypi |
| Risk score | 80 / 100 (high) |
| Published | 2026-11-24T09:17:04Z |
| Scanned | 2026-11-25T11:39:06Z |
| Registry page | https://pypi.org/project/buckthorn/0.2.0/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it. (in 6 files)

  Evidence in `buckthorn-0.2.0/tests/test_call_time.py`:

  ```text
  version = "__version__ = '1.0'\nimport base64\ndef get():\n exec(base64.b64decode(B))\n"
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `buckthorn/code.py`:

  ```text
  r"\b(?:curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|certutil|bitsadmin)\b|https?://",
  ```


## Suggested text for an upstream report

The pypi package `buckthorn` version `0.2.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it. (in 6 files)
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fbuckthorn%400.2.0&package=pypi%2Fbuckthorn%400.2.0
