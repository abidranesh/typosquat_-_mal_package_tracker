# Suspicious package report: `dj-sc-digger` 1.7.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `dj-sc-digger` |
| Version | `1.7.0` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-23T00:04:42Z |
| Scanned | 2026-11-24T06:16:30Z |
| Registry page | https://pypi.org/project/dj-sc-digger/1.7.0/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `dj_digger/auth.py`:

  ```text
  copy = os.path.join(scratch, "cookies.sqlite")
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `dj_sc_digger-1.7.0/packaging/windows/build.py`:

  ```text
  with urlopen(spec['url'], timeout=60) as source, destination.open('wb') as output:
  ```


## Suggested text for an upstream report

The pypi package `dj-sc-digger` version `1.7.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fdj-sc-digger%401.7.0&package=pypi%2Fdj-sc-digger%401.7.0
