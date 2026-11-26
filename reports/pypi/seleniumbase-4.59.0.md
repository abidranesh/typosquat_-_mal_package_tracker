# Suspicious package report: `seleniumbase` 4.59.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `seleniumbase` |
| Version | `4.59.0` |
| Ecosystem | pypi |
| Risk score | 90 / 100 (high) |
| Published | 2026-11-25T07:26:54Z |
| Scanned | 2026-11-26T12:59:41Z |
| Registry page | https://pypi.org/project/seleniumbase/4.59.0/ |

## Indicators

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `seleniumbase/core/browser_launcher.py`:

  ```text
  response = requests.get(url, proxies=proxies, timeout=1.25)
  ```

- **python-install-code** (medium, +30): setup.py exec() runs dynamically built code at install time.

  Evidence in `seleniumbase-4.59.0/setup.py:30`:

  ```text
  exec(f.read().decode("utf-8"), about)
  ```

- **python-install-code** (medium, +25): setup.py os.system() starts a process at install time.

  Evidence in `seleniumbase-4.59.0/setup.py:44`:

  ```text
  os.system("python -m pip install 'flake8==7.5.0'")
  ```


## Suggested text for an upstream report

The pypi package `seleniumbase` version `4.59.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code downloads a file and then executes it or marks it executable.
- setup.py exec() runs dynamically built code at install time.
- setup.py os.system() starts a process at install time.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fseleniumbase%404.59.0&package=pypi%2Fseleniumbase%404.59.0
