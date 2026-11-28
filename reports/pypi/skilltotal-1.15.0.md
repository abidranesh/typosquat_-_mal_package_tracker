# Suspicious package report: `skilltotal` 1.15.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `skilltotal` |
| Version | `1.15.0` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-26T23:11:11Z |
| Scanned | 2026-11-28T04:42:45Z |
| Registry page | https://pypi.org/project/skilltotal/1.15.0/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it. (in 5 files)

  Evidence in `skilltotal/scanners/pth_exec.py`:

  ```text
  the signature of a malicious payload (e.g. ``exec(base64.b64decode(...))``). A bare ``exec`` of
  ```

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `skilltotal/engine.py`:

  ```text
  # `open("~/.aws/credentials")` in .py/.js, which is unaffected (efficacy positives are code).
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `skilltotal/file_index.py`:

  ```text
  `echo " curl -LsSf https://astral.sh/uv/install.sh | sh"` and
  ```

- **exfiltration** (medium, +30): Code serialises the whole process environment in a file that makes network calls.

  Evidence in `skilltotal/scanners/secret_exfil.py`:

  ```text
  @~/.ssh/id_rsa https://...``, ``cat ~/.aws/credentials | curl --data-binary @- ...``, ``env |
  ```


## Suggested text for an upstream report

The pypi package `skilltotal` version `1.15.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it. (in 5 files)
- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Code serialises the whole process environment in a file that makes network calls.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fskilltotal%401.15.0&package=pypi%2Fskilltotal%401.15.0
