# Suspicious package report: `stackops` 26.11.10 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `stackops` |
| Version | `26.11.10` |
| Ecosystem | pypi |
| Risk score | 80 / 100 (high) |
| Published | 2026-11-26T23:35:27Z |
| Scanned | 2026-11-28T04:42:45Z |
| Registry page | https://pypi.org/project/stackops/26.11.10/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `stackops/scripts/python/helpers/helpers_sessions/sessions_test_layouts.py`:

  ```text
  f"exec(base64.b64decode('{_INLINE_WORKER_SCRIPT_B64}').decode('utf-8'))"
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `stackops/utils/installer_utils/package_manager_installation.py`:

  ```text
  response = requests.get(script_url, timeout=60)
  ```


## Suggested text for an upstream report

The pypi package `stackops` version `26.11.10` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fstackops%4026.11.10&package=pypi%2Fstackops%4026.11.10
