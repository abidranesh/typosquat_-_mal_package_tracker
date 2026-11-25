# Suspicious package report: `nwolk` 0.1.5 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `nwolk` |
| Version | `0.1.5` |
| Ecosystem | pypi |
| Risk score | 79 / 100 (high) |
| Published | 2026-11-24T17:17:24Z |
| Scanned | 2026-11-25T20:42:00Z |
| Registry page | https://pypi.org/project/nwolk/0.1.5/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `nwolk/_bundle/nwolk.cjs`:

  ```text
  import_path2.default.join(home, ".ssh", "id_ed25519.pub"),
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `nwolk/_bundle/nwolk.cjs`:

  ```text
  console.log(style.dim(" Linux/macOS: curl -fsSL https://pkgs.netbird.io/install.sh | sh"));
  ```

- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The pypi package `nwolk` version `0.1.5` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fnwolk%400.1.5&package=pypi%2Fnwolk%400.1.5
