# Suspicious package report: `waku-agent` 0.1.15 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `waku-agent` |
| Version | `0.1.15` |
| Ecosystem | pypi |
| Risk score | 70 / 100 (high) |
| Published | 2026-11-23T02:03:50Z |
| Scanned | 2026-11-24T06:16:30Z |
| Registry page | https://pypi.org/project/waku-agent/0.1.15/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `waku_agent-0.1.15/evals/deterministic/test_plugin_install.py`:

  ```text
  links=(("repo-main/link", "/etc/passwd"),))
  ```

- **suspicious-endpoint** (medium, +30): Hardcoded ngrok tunnel in package code.

  Evidence in `waku/gateway/whatsapp.py`:

  ```text
  - Copy the https://xxxx.ngrok.io URL
  ```


## Suggested text for an upstream report

The pypi package `waku-agent` version `0.1.15` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Hardcoded ngrok tunnel in package code.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fwaku-agent%400.1.15&package=pypi%2Fwaku-agent%400.1.15
