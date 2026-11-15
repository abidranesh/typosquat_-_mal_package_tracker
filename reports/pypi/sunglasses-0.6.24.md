# Suspicious package report: `sunglasses` 0.6.24 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `sunglasses` |
| Version | `0.6.24` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-15T14:54:29Z |
| Scanned | 2026-11-15T17:55:06Z |
| Registry page | https://pypi.org/project/sunglasses/0.6.24/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `sunglasses/firewall.py`:

  ```text
  # `- ~/.ssh/id_rsa\x00` parsed cleanly, never matched the path it names, and
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `sunglasses/patterns.py`:

  ```text
  # one-liner (ollama/deno/grype: `curl https://… | sudo sh`) is
  ```

- **exfiltration** (medium, +30): Code serialises the whole process environment in a file that makes network calls.

  Evidence in `sunglasses/validators.py`:

  ```text
  (``len``, ``.upper()``), a precision, names only, and ``json.dumps(os.environ)`` (which raises
  ```


## Suggested text for an upstream report

The pypi package `sunglasses` version `0.6.24` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Code serialises the whole process environment in a file that makes network calls.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fsunglasses%400.6.24&package=pypi%2Fsunglasses%400.6.24
