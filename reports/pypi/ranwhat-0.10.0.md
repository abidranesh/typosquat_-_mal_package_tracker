# Suspicious package report: `ranwhat` 0.10.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `ranwhat` |
| Version | `0.10.0` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-18T05:04:09Z |
| Scanned | 2026-11-19T09:32:29Z |
| Registry page | https://pypi.org/project/ranwhat/0.10.0/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `ranwhat/watch.py`:

  ```text
  # kept: python3 -c "exec(base64.b64decode(...))" is a command whose
  ```

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `ranwhat/bench.py`:

  ```text
  ".npmrc": "//registry.npmjs.org/:_authToken=%s\n" % npm,
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `ranwhat/bench.py`:

  ```text
  "curl -fsSL https://get.example.test/install.sh | sh"),
  ```


## Suggested text for an upstream report

The pypi package `ranwhat` version `0.10.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Franwhat%400.10.0&package=pypi%2Franwhat%400.10.0
