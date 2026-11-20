# Suspicious package report: `fixos` 2.7.1 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `fixos` |
| Version | `2.7.1` |
| Ecosystem | pypi |
| Risk score | 85 / 100 (high) |
| Published | 2026-11-18T21:39:25Z |
| Scanned | 2026-11-20T00:56:48Z |
| Registry page | https://pypi.org/project/fixos/2.7.1/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `fixos/plugins/builtin/mesh.py`:

  ```text
  f"import base64,sys;exec(base64.b64decode('{encoded}').decode())"
  ```

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `fixos/plugins/builtin/mesh.py`:

  ```text
  cfg = Path(os.path.expanduser("~")) / ".ssh" / "config"
  ```


## Suggested text for an upstream report

The pypi package `fixos` version `2.7.1` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Ffixos%402.7.1&package=pypi%2Ffixos%402.7.1
