# Suspicious package report: `kcli` 99.0.202611261841 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `kcli` |
| Version | `99.0.202611261841` |
| Ecosystem | pypi |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-26T18:41:41Z |
| Scanned | 2026-11-27T22:51:54Z |
| Registry page | https://pypi.org/project/kcli/99.0.202611261841/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `kvirt/baseconfig.py`:

  ```text
  orissh = f"{tmpdir}/.ssh"
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `kvirt/cluster/rke2/bootstrap.sh`:

  ```text
  curl -sfL https://get.rke2.io | sh -
  ```


## Suggested text for an upstream report

The pypi package `kcli` version `99.0.202611261841` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fkcli%4099.0.202611261841&package=pypi%2Fkcli%4099.0.202611261841
