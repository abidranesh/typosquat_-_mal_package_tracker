# Suspicious package report: `vloex-mcp-proxy` 0.6.4 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `vloex-mcp-proxy` |
| Version | `0.6.4` |
| Ecosystem | pypi |
| Risk score | 83 / 100 (high) |
| Published | 2026-11-15T16:46:02Z |
| Scanned | 2026-11-15T22:45:36Z |
| Registry page | https://pypi.org/project/vloex-mcp-proxy/0.6.4/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it. (in 2 files)

  Evidence in `vloex_mcp_proxy/skillscan/rules.py`:

  ```text
  "eval(atob(…)), exec(base64.b64decode(…))).",
  ```

- **exfiltration** (medium, +30): Code serialises the whole process environment in a file that makes network calls.

  Evidence in `vloex_mcp_proxy/skillscan/rules.py`:

  ```text
  r"(?:\$\(\s*(?:env|printenv|set)\s*\)|`\s*(?:env|printenv)\s*`|\b(?:env|printenv)\s*\|"
  ```

- **sparse-metadata** (info, +8): Missing or placeholder README, repository URL.

## Suggested text for an upstream report

The pypi package `vloex-mcp-proxy` version `0.6.4` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it. (in 2 files)
- Code serialises the whole process environment in a file that makes network calls.
- Missing or placeholder README, repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fvloex-mcp-proxy%400.6.4&package=pypi%2Fvloex-mcp-proxy%400.6.4
