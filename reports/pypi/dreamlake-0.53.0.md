# Suspicious package report: `dreamlake` 0.53.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `dreamlake` |
| Version | `0.53.0` |
| Ecosystem | pypi |
| Risk score | 84 / 100 (high) |
| Published | 2026-11-16T02:02:00Z |
| Scanned | 2026-11-16T20:28:36Z |
| Registry page | https://pypi.org/project/dreamlake/0.53.0/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it. (in 2 files)

  Evidence in `dreamlake/api/hosts.py`:

  ```text
  command = f"python3 -c 'import base64;exec(base64.b64decode(\"{encoded}\"))'"
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `dreamlake/cli/_notice.py`:

  ```text
  ``curl -fsSL https://dl.dreamlake.ai/install.sh | bash`` — every
  ```

- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The pypi package `dreamlake` version `0.53.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it. (in 2 files)
- Code downloads a file and then executes it or marks it executable.
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fdreamlake%400.53.0&package=pypi%2Fdreamlake%400.53.0
