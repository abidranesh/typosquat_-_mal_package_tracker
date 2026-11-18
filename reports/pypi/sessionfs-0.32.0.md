# Suspicious package report: `sessionfs` 0.32.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `sessionfs` |
| Version | `0.32.0` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-17T06:55:05Z |
| Scanned | 2026-11-18T11:32:27Z |
| Registry page | https://pypi.org/project/sessionfs/0.32.0/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `sessionfs/skills/instruction_scan.py`:

  ```text
  "Evaluates decoded or decompressed data (exec(base64...), eval(atob(...)))."),
  ```

- **exfiltration** (medium, +30): Code serialises the whole process environment in a file that makes network calls.

  Evidence in `sessionfs/skills/instruction_scan.py`:

  ```text
  _ENV_PIPE = re.compile(r"\b(?:printenv|env|get-childitem\s{1,4}env:|gci\s{1,4}env:)\s{0,4}\|", _I)
  ```


## Suggested text for an upstream report

The pypi package `sessionfs` version `0.32.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Code serialises the whole process environment in a file that makes network calls.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fsessionfs%400.32.0&package=pypi%2Fsessionfs%400.32.0
