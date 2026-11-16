# Suspicious package report: `argus-scan` 0.7.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `argus-scan` |
| Version | `0.7.0` |
| Ecosystem | pypi |
| Risk score | 80 / 100 (high) |
| Published | 2026-11-15T19:51:43Z |
| Scanned | 2026-11-16T02:25:52Z |
| Registry page | https://pypi.org/project/argus-scan/0.7.0/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it. (in 2 files)

  Evidence in `argus_scan-0.7.0/tests/test_malware_obfuscation.py`:

  ```text
  (f'eval(atob("{BASE64}"));', "malware-js-eval-encoded-literal", Severity.HIGH),
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `argus/server.py`:

  ```text
  "install": "brew install trivy OR curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh",
  ```


## Suggested text for an upstream report

The pypi package `argus-scan` version `0.7.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it. (in 2 files)
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fargus-scan%400.7.0&package=pypi%2Fargus-scan%400.7.0
