# Suspicious package report: `reportlab` 5.1.1 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `reportlab` |
| Version | `5.1.1` |
| Ecosystem | pypi |
| Risk score | 88 / 100 (high) |
| Published | 2026-11-24T16:12:59Z |
| Scanned | 2026-11-25T20:42:00Z |
| Registry page | https://pypi.org/project/reportlab/5.1.1/ |

## Indicators

- **python-install-code** (medium, +30): setup.py exec() runs dynamically built code at install time.

  Evidence in `reportlab-5.1.1/setup.py:87`:

  ```text
  exec(l.strip(),D)
  ```

- **python-install-code** (medium, +25): setup.py subprocess.call() starts a process at install time.

  Evidence in `reportlab-5.1.1/setup.py:37`:

  ```text
  r = subprocess.call(
  ```

- **python-install-code** (medium, +25): setup.py urllib.request.build_opener() opens a network connection at install time.

  Evidence in `reportlab-5.1.1/setup.py:190`:

  ```text
  opener = ureq.build_opener()
  ```

- **obfuscation** (low, +8): Long base64 or hex blob embedded in source code. (in 2 files)

  Evidence in `reportlab-5.1.1/tests/test_platypus_cjk_wrap.py`:

  ```text
  \xe3\x82\xac\xe3\x83\x88\xe3\x82\xa6\xe3\x82\xa3\xe3\x83\x83\xe3\x82\xaf\xe7\xa9\xba\xe6\xb8\xaf\xe3\x81\xa8\xe9\x80\xa3\xe7\xb5\xa1\xe9\x80\x9a\xe8\xb7\xaf\xe3\x81\xa7\xe7\x9b\xb4\xe7\xb5\x90\xe3\x8…
  ```


## Suggested text for an upstream report

The pypi package `reportlab` version `5.1.1` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- setup.py exec() runs dynamically built code at install time.
- setup.py subprocess.call() starts a process at install time.
- setup.py urllib.request.build_opener() opens a network connection at install time.
- Long base64 or hex blob embedded in source code. (in 2 files)

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Freportlab%405.1.1&package=pypi%2Freportlab%405.1.1
