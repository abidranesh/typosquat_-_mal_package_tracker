# Suspicious package report: `secator` 0.57.1 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `secator` |
| Version | `0.57.1` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-26T22:25:06Z |
| Scanned | 2026-11-28T04:42:45Z |
| Registry page | https://pypi.org/project/secator/0.57.1/ |
| Possibly imitating | `vector` |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `secator/ai/guardrails.py`:

  ```text
  network host does (an IP, ``localhost``, or a dotted name), so ``cat //etc/passwd``
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `secator/installer.py`:

  ```text
  rust_install_cmd = 'curl https://sh.rustup.rs -sSf | sh -s -- -y'
  ```

- **suspicious-endpoint** (medium, +20): URL with a raw IP address instead of a hostname.

  Evidence in `secator/scope.py`:

  ```text
  # IP literal hiding in a url / host:port (8.8.8.8:443, http://8.8.8.8/) --
  ```

- **typosquat** (low, +6): Name is 2 edit(s) from popular package 'vector' (two edits apart).

## Suggested text for an upstream report

The pypi package `secator` version `0.57.1` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- URL with a raw IP address instead of a hostname.
- Name is 2 edit(s) from popular package 'vector' (two edits apart).

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fsecator%400.57.1&package=pypi%2Fsecator%400.57.1
