# Suspicious package report: `mcp-audit-scanner` 0.35.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `mcp-audit-scanner` |
| Version | `0.35.0` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-20T11:22:41Z |
| Scanned | 2026-11-21T20:04:05Z |
| Registry page | https://pypi.org/project/mcp-audit-scanner/0.35.0/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `mcp_audit_scanner-0.35.0/tests/test_install_steps.py`:

  ```text
  "exec(__import__('base64').b64decode('cHJpbnQoMSk='))",
  ```

- **exfiltration** (medium, +30): Code serialises the whole process environment in a file that makes network calls.

  Evidence in `mcp_audit/agent_files/exfil.py`:

  ```text
  r"|\b(?:dump|output|contents)\s+of\s+`?(?:env|printenv|set)\b"
  ```

- **suspicious-endpoint** (medium, +30): Hardcoded Pipedream endpoint in package code.

  Evidence in `mcp_audit/registration/client.py`:

  ```text
  _REGISTER_ENDPOINT = "https://eo4jvaanlkuohuc.m.pipedream.net"
  ```


## Suggested text for an upstream report

The pypi package `mcp-audit-scanner` version `0.35.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Code serialises the whole process environment in a file that makes network calls.
- Hardcoded Pipedream endpoint in package code.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fmcp-audit-scanner%400.35.0&package=pypi%2Fmcp-audit-scanner%400.35.0
