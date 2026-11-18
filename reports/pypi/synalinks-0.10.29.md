# Suspicious package report: `synalinks` 0.10.29 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `synalinks` |
| Version | `0.10.29` |
| Ecosystem | pypi |
| Risk score | 85 / 100 (high) |
| Published | 2026-11-17T15:41:27Z |
| Scanned | 2026-11-18T19:38:35Z |
| Registry page | https://pypi.org/project/synalinks/0.10.29/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `synalinks/src/utils/sandbox_bootstrap_utils.py`:

  ```text
  LAUNCHER = "import base64,sys;exec(base64.b64decode(sys.argv[1]))"
  ```

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `synalinks/src/sandboxes/mirage_sandbox_test.py`:

  ```text
  "print('passwd', os.path.exists('/etc/passwd'))\n"
  ```


## Suggested text for an upstream report

The pypi package `synalinks` version `0.10.29` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fsynalinks%400.10.29&package=pypi%2Fsynalinks%400.10.29
