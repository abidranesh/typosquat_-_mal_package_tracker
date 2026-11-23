# Suspicious package report: `stayawakebot` 0.17.4 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `stayawakebot` |
| Version | `0.17.4` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-22T17:31:14Z |
| Scanned | 2026-11-23T22:15:55Z |
| Registry page | https://pypi.org/project/stayawakebot/0.17.4/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `stayawake/bots/security/remediation/gates.py`:

  ```text
  EARLIER obfuscation stage where the literal isn't present yet but an `eval(atob(...))`
  ```

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `stayawake/bots/security/hygiene/mechanism.py`:

  ```text
  title=f"~/.ssh/{name} is world-writable",
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `stayawake/bots/security/matchers/command_shape.py`:

  ```text
  r"|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|recv|file_get_contents|curl|wget)")
  ```


## Suggested text for an upstream report

The pypi package `stayawakebot` version `0.17.4` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fstayawakebot%400.17.4&package=pypi%2Fstayawakebot%400.17.4
