# Suspicious package report: `taskuary` 0.4.1.8 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `taskuary` |
| Version | `0.4.1.8` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-23T01:37:38Z |
| Scanned | 2026-11-24T06:16:30Z |
| Registry page | https://pypi.org/project/taskuary/0.4.1.8/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `taskuary-0.4.1.8/taskuary/readgate.py`:

  ```text
  # ...a `${NAME}` is one word, never a block's braces: cut there, `cat ${HOME}/.ssh/x` named only `/.ssh/x`, which exists nowhere
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `taskuary-0.4.1.8/taskuary/cliinstall.py`:

  ```text
  {'how': 'script', 'os': 'posix', 'cmd': ['bash', '-lc', 'curl -fsSL https://claude.ai/install.sh | bash']},
  ```


## Suggested text for an upstream report

The pypi package `taskuary` version `0.4.1.8` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Ftaskuary%400.4.1.8&package=pypi%2Ftaskuary%400.4.1.8
