# Suspicious package report: `clankit` 0.1.7 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `clankit` |
| Version | `0.1.7` |
| Ecosystem | pypi |
| Risk score | 81 / 100 (high) |
| Published | 2026-11-19T19:19:10Z |
| Scanned | 2026-11-20T23:15:56Z |
| Registry page | https://pypi.org/project/clankit/0.1.7/ |
| Possibly imitating | `clikit` |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `clankit-0.1.7/tests/test_skills_safety.py`:

  ```text
  ("exec(base64.b64decode(blob))", "decodes and executes hidden code"),
  ```

- **new-publisher-similar-name** (medium, +20): Recently created package from a publisher with little history, with a name similar to popular package 'clikit'.
- **typosquat** (low, +12): Name is 2 edit(s) from popular package 'clikit' (two edits apart).
- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The pypi package `clankit` version `0.1.7` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Recently created package from a publisher with little history, with a name similar to popular package 'clikit'.
- Name is 2 edit(s) from popular package 'clikit' (two edits apart).
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fclankit%400.1.7&package=pypi%2Fclankit%400.1.7
