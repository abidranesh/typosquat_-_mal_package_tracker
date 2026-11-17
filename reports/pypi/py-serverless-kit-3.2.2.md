# Suspicious package report: `py-serverless-kit` 3.2.2 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `py-serverless-kit` |
| Version | `3.2.2` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-16T10:35:11Z |
| Scanned | 2026-11-17T12:17:23Z |
| Registry page | https://pypi.org/project/py-serverless-kit/3.2.2/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `py_serverless_kit/core/onprem_services.py`:

  ```text
  "(grep -qxF \"$k\" ~/.ssh/authorized_keys || printf '%s\\n' \"$k\" >> ~/.ssh/authorized_keys)")
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `py_serverless_kit/studio/vscode.py`:

  ```text
  f"RUN curl -LsSf https://astral.sh/uv/{UV_VERSION}/install.sh | sh"
  ```


## Suggested text for an upstream report

The pypi package `py-serverless-kit` version `3.2.2` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fpy-serverless-kit%403.2.2&package=pypi%2Fpy-serverless-kit%403.2.2
